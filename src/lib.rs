use std::thread;
use std::sync::{Arc,Barrier,Mutex};
use std::io;
use std::time::{Instant, Duration};

use goblin::elf::Elf;
use goblin::elf::program_header::PT_LOAD;

use crossbeam::channel::{self, select};

use vmm_sys_util::signal::Killable;
use kvm_ioctls::{Kvm, VmFd, VcpuFd, VcpuExit};
use memmap::MmapMut;

use scoped_signal::{SignalScope, SigSet, SaFlags, Signal};

pub mod mem;
use mem::MemAlloc;

mod util;
use util::KillableThread;

/// Press F
#[derive(Debug, Clone)]
pub struct Tombstone {
    pub death_time: Instant,
    pub program_id: usize,
    pub thread_id: u8,
    pub forced: bool
}

impl Tombstone {
    fn new(death_time: Instant, program_id: usize, thread_id: u8, forced: bool) -> Self {
        Self {
            death_time,
            program_id,
            thread_id,
            forced
        }
    }
}

#[repr(C,align(4096))]
struct Exclusive ([u8; 4096]);

impl Exclusive {
    fn new() -> Self {
        Self([0; 4096])
    }
}

struct Program {
    vm: VmFd,
    cores: Vec<VMCore>,
    entry: u64,
    cr3: u64,
    stack: u64,
    exclusive: Mutex<Box<Exclusive>>,
    exclusive_addr: u64,
}

impl Program {
    /// Make a new VM using the given memory
    pub fn new(kvm: &Kvm, mem: &mut MmapMut, entry: u64, cr3: u64, stack: u64) -> Self {
        let vm = kvm.create_vm().unwrap();


        let mem_region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: mem.len() as u64,
            userspace_addr: (&mut mem[0] as *mut u8) as u64,
            flags: 0
        };
        unsafe { vm.set_user_memory_region(mem_region).unwrap() };

        let mut exclusive = Box::from(Exclusive::new());

        let exclusive_addr = mem.len() as u64;

        let exclusive_region = kvm_bindings::kvm_userspace_memory_region {
            slot: 1,
            guest_phys_addr: exclusive_addr,
            memory_size: 4096,
            userspace_addr: exclusive.0.as_mut_ptr() as u64,
            flags: 0,
        };
        unsafe { vm.set_user_memory_region(exclusive_region).unwrap() };

        Self {
            vm,
            cores: vec![],
            entry,
            cr3,
            stack,
            exclusive: Mutex::new(exclusive),
            exclusive_addr
        }
    }

    pub fn core_count(&self) -> u8 {
        self.cores.len() as u8
    }

    fn with_exclusive<T,F: FnMut(&mut Exclusive) -> T>(&self, mut f: F) ->T {
        let mut exclusive = self.exclusive.lock().unwrap();

        let exclusive_region_immut = kvm_bindings::kvm_userspace_memory_region {
            slot: 1,
            guest_phys_addr: self.exclusive_addr,
            memory_size: 0,
            userspace_addr: exclusive.0.as_ptr() as u64,
            flags: 0
            //flags: kvm_bindings::KVM_MEM_READONLY // doesn't work on my machine
        };

        let res = unsafe { self.vm.set_user_memory_region(exclusive_region_immut) };
        res.unwrap();

        let ret = f(&mut exclusive);

        let exclusive_region_mut = kvm_bindings::kvm_userspace_memory_region {
            slot: 1,
            guest_phys_addr: self.exclusive_addr,
            memory_size: 4096,
            userspace_addr: exclusive.0.as_mut_ptr() as u64,
            flags: 0
        };

        unsafe { self.vm.set_user_memory_region(exclusive_region_mut).unwrap() };

        ret
    }

    /// Create a new core for our VM
    pub fn new_core(&mut self) -> u8 {
        let id = self.cores.len() as u8;
        let c = VMCore::new(self.vm.create_vcpu(id).unwrap());
        c.load_registers(self.entry, self.cr3, self.stack, self.exclusive_addr);
        self.cores.push(c);
        id
    }

    pub fn run_core(&self, _program_id: usize, core_id: u8, chan: &channel::Sender<HyperMessage>) -> io::Result<bool> {
        loop {
            match self.cores[core_id as usize].run() {
                Ok(VcpuExit::Hlt) => {
                    let mut regs = self.cores[core_id as usize].vcpu.get_regs().unwrap();
                    regs.rax = match regs.rax {
                        // Print Text
                        1 => {
                            let mem = self.with_exclusive(|e| {
                                e.0.clone()
                            });
                            let offset = regs.rdi as usize;
                            let len = regs.rsi as usize;
                            if offset < mem.len() && (offset + len) < mem.len() {
                                if let Ok(s) = std::str::from_utf8(&mem[offset..(offset + len)]) {
                                    chan.send(HyperMessage::Print(s.to_owned())).unwrap();
                                    0
                                } else {
                                    std::u64::MAX
                                }
                            } else {
                                std::u64::MAX
                            }
                        }
                        // Submit value
                        2 => {
                            println!("HALT: {:?}", regs.rax);
                            self.with_exclusive(|e| {
                                e.0
                            });
                            0
                        }
                        _ => {
                            println!("HALT: {:?}", regs.rax);
                            std::u64::MAX
                        }
                    };
                    self.cores[core_id as usize].vcpu.set_regs(&regs).unwrap();
                }
                Ok(VcpuExit::Shutdown) => {
                    //let regs = self.cores[core_id as usize].vcpu.get_regs().unwrap();
                    //println!("Shutting down {:?}", regs);
                    break
                }
                Ok(e) => {
                    println!("save me");
                    panic!("unexpected vcpu exit {:?}", e);
                }
                Err(e) => {
                    match e.kind() {
                        io::ErrorKind::Interrupted => {
                            let regs = self.cores[core_id as usize].vcpu.get_regs().unwrap();
                            println!("Commanded shut down {:?}", regs);
                            return Ok(true);
                        }
                        _ => {
                            Err(e)?
                        }
                    }
                }
            }
        }
        Ok(false)
    }
}

pub struct Arena {
    mem: MemAlloc,
    kvm: Kvm,
    programs: Vec<Program>
}

impl Arena {
    pub fn new(mem: MemAlloc) -> Self {
        let kvm = Kvm::new().unwrap();
        Self {
            mem,
            kvm,
            programs: vec![],
        }
    }

    /// Executable is a byte slice cotaining a valid x86-64 elf executable
    pub fn load<B: AsRef<[u8]>>(&mut self, executable: B) -> usize {
        let executable = executable.as_ref();
        let elf = Elf::parse(&executable.as_ref()).unwrap();

        let cr3 = self.mem.create_pml4() * 4096;
        for h in elf.program_headers {
            if h.p_type != PT_LOAD {
                continue
            }
            let mut code = vec![0; h.p_memsz as usize];
            if h.p_filesz > 0 {
                code.copy_from_slice(&executable[h.p_offset as usize..(h.p_offset as usize + h.p_filesz as usize)]);
            }
            self.mem.load(cr3 as usize, &code, h.p_vaddr as usize);
        }
        let entry = elf.header.e_entry;
        let stack = 0x00007FFFFFFFDFFF;
        for i in 0..100 {
            self.mem.lookup_or_allocate(cr3 as usize, (stack - (stack % 4096) - (4096 * i)) as usize);
        }
        self.mem.identity_map(cr3 as usize, 0xFFFF800000000000);

        self.mem.map(cr3 as usize, self.mem.backing.len() as u64, 0x00007FFFFFFFE000);

        let mut prog = Program::new(&self.kvm, &mut self.mem.backing, entry, cr3, stack);
        prog.new_core();
        let idx = self.programs.len();
        self.programs.push(prog);
        idx
    }

    /// Run all programs
    pub fn run(self) -> ArenaHandle {
        ArenaHandle::new(self)
    }

    fn run_threads(&mut self, msend: channel::Sender<ArenaMessage>, crecv: channel::Receiver<ArenaCommand>) {
        let num_cores = self.programs.iter().map(|p|p.core_count() as usize).sum();

        let (send, recv) = channel::bounded::<HyperMessage>(num_cores);

        let barrier = Arc::new(Barrier::new(num_cores + 1));
        crossbeam::scope(|scope| {
            let handles: Vec<_> = self.programs.iter().enumerate().flat_map(|(id, p)| {
                (0..p.core_count()).map( move |tid|{
                    (p, id, tid)
                })
            }).map(|(p, id, tid)| {
                let s = send.clone();
                let b = barrier.clone();
                let handle: KillableThread<_> = scope.spawn(move |_|{
                    let vcpufd = &p.cores[tid as usize].vcpu;
                    let handler_fn = |signo, _info: &_| {
                        vcpufd.set_kvm_immediate_exit(signo as u8);
                    };
                    let handler = unsafe { SignalScope::new(Signal::SIGUSR1, SaFlags::empty(), SigSet::empty(), handler_fn) };
                    handler.run(|| {
                        b.wait();
                        let forced = p.run_core(id, tid, &s).unwrap_or(false);
                        let death_time = Instant::now();
                        let tomb = Tombstone::new(death_time, id, tid, forced);
                        s.send(HyperMessage::Shutdown(tomb)).expect("Failed to send death message to VMM");
                    }).expect("Failed to spawn VM thread");
                }).into();
                handle
            }).collect();

            let start = Instant::now();
            barrier.wait();


            let mut deaths = vec![];

            drop(send); // This way the channel closes
            loop {
                select! { 
                    recv(recv) -> msg => match msg {
                            Ok(HyperMessage::Print(s)) => {
                                print!("{}", s);
                            }
                            Ok(HyperMessage::Shutdown(tombstone)) => {
                                msend.send(ArenaMessage::Death(tombstone.clone())).expect("Failed to send death message");
                                deaths.push(tombstone);
                            }
                            Err(e) => {
                                println!("HyperMessageError: {:?}", e);
                                break
                            }
                        },
                    recv(crecv) -> msg => match msg {
                            Ok(ArenaCommand::Shutdown) => {
                                println!("Shutdown commanded");
                                for h in &handles {
                                    match h.kill(10) {
                                        Err(e) => panic!("Failed to kill thread {:?}: {:?}", h, e),
                                        _ => {}
                                    }
                                }
                            }
                            Err(e) => {
                                println!("ArenaCommandError: {:?}", e);
                            }
                        }
                }
            }
            println!("halp");
            msend.send(ArenaMessage::Shutdown(start, deaths)).expect("Failed to send tombstones");
        }).unwrap()
    }
}

pub struct ArenaHandle {
    pub send: channel::Sender<ArenaCommand>,
    pub recv: channel::Receiver<ArenaMessage>,
    handle: thread::JoinHandle<()>
}

impl ArenaHandle {
    fn new(mut arena: Arena) -> Self {
        let (msend, mrecv) = channel::bounded(16); // TODO: decide on a good limit here
        let (csend, crecv) = channel::bounded(16);
        Self {
            send: csend,
            recv: mrecv,
            handle: 
                thread::spawn(move || {
                    arena.run_threads(msend, crecv)
                })
        }
    }
    pub fn join(self) -> Result<(), Box<dyn std::any::Any + Send>> {
        self.handle.join()
    }
    pub fn wait(self, timeout: Option<Duration>) -> Result<(Instant, Vec<Tombstone>),()> {
        self.wait2(timeout, |msg| {
            match msg {
                ArenaMessage::Death(tombstone) => println!("Death of program {} core {}", tombstone.program_id, tombstone.thread_id),
                _ => {}
            }
        })
    }
    pub fn wait2<F: FnMut(ArenaMessage)>(self, timeout: Option<Duration>, mut f: F) -> Result<(Instant, Vec<Tombstone>),()> {
        let timeout = timeout.map(|d| channel::after(d)).unwrap_or(channel::never());
        loop {
            select! {
                recv(self.recv) -> msg => match msg {
                        Ok(ArenaMessage::Shutdown(s, d)) => return Ok((s,d)),
                        Ok(msg) => f(msg),
                        Err(_e) => Err(())?
                    },
                recv(timeout) -> _ => {
                    self.send.send(ArenaCommand::Shutdown).expect("failed to send shutdown command");
                }
            }
        }
    }
}

pub enum ArenaCommand {
    Shutdown
}

pub enum ArenaMessage {
    Death(Tombstone),
    Shutdown(Instant, Vec<Tombstone>)
}

enum HyperMessage {
    Print(String),
    Shutdown(Tombstone)
}

/// One core of our virtual machine
pub struct VMCore {
    vcpu: VcpuFd
}

impl VMCore {
    fn new(vcpu: VcpuFd) -> Self {
        let mut vcpu_sregs = vcpu.get_sregs().unwrap();
        vcpu_sregs.cr4 = 0b10100000;
        vcpu_sregs.efer |= 0x00000500; // If we don't set bit 4 we get big stinky error when we set_sregs
        vcpu_sregs.cr0 |= 0x80000001;

        // Who needs a GDT, anyways?
        vcpu_sregs.cs.db = 0;
        vcpu_sregs.cs.l = 1;
        vcpu_sregs.cs.present = 1;
        vcpu_sregs.cs.dpl = 0;
        vcpu_sregs.cs.type_ = 0b1000;
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.limit = 0;

        vcpu.set_sregs(&vcpu_sregs).unwrap();

        //let mut vcpu_regs = vcpu.get_regs().unwrap();
        //vcpu_regs.rip = guest_addr;
        //vcpu.set_regs(&vcpu_regs).unwrap();

        Self {
            vcpu
        }
    }

    pub fn load_registers(&self, entry: u64, cr3: u64, stack: u64, mem_len: u64) {
        let mut vcpu_sregs = self.vcpu.get_sregs().unwrap();
        vcpu_sregs.cr3 = cr3;
        self.vcpu.set_sregs(&vcpu_sregs).unwrap();

        let mut vcpu_regs = self.vcpu.get_regs().unwrap();
        vcpu_regs.rip = entry;
        vcpu_regs.rsp = stack;
        vcpu_regs.rdi = mem_len;
        self.vcpu.set_regs(&vcpu_regs).unwrap();
    }

    pub fn run(&self) -> io::Result<VcpuExit> {
        self.vcpu.run()
    }
}
