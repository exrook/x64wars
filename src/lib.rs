use std::thread;
use std::sync::{Arc,Barrier,Mutex};

use goblin::elf::Elf;
use goblin::elf::program_header::PT_LOAD;

use crossbeam::channel;

use kvm_ioctls::{Kvm, VmFd, VcpuFd, VcpuExit};
use memmap::{MmapOptions,MmapMut};
use rand::seq::SliceRandom;
use rand::thread_rng;
use x86::bits64::paging::*;

/// A memory backing for our VM
#[derive(Debug)]
pub struct MemAlloc {
    backing: MmapMut,
    free: Vec<u64>
}

impl MemAlloc {
    /// Allocate a memory region of size `size`, size must be a multiple of 4096
    pub fn new(size: usize) -> Self {
        assert_eq!(size % 4096, 0, "size must be a multiple of 4096");
        let mut free: Vec<_> = (0..(size as u64/4096)).collect();
        free.shuffle(&mut thread_rng());
        Self {
            backing: MmapOptions::new().len(size).map_anon().unwrap(),
            free
        }
    }

    pub fn identity_map(&mut self, pml4_address: usize, identity_base: u64) {
        for i in 0..(self.backing.len() / 4096) {
            self.map(pml4_address, i as u64 * 4096, identity_base + (i as u64 * 4096));
        }
    }

    /// Copy `code` to the location `base_vaddr` address in the `pml4_address` address space,
    /// perserving existing mappings if present, creating new ones if not
    pub fn load2(&mut self, pml4_address: usize, code: &[u8], base_vaddr: usize) {
        let mut i = base_vaddr as usize;
        let section_end = base_vaddr as usize + code.len() - 1;
        while i < (section_end + 1) {
            let chunk_start = i;
            let page_addr = (chunk_start / 4096)*4096;
            let chunk_end = section_end.min(page_addr + 4095);

            let backing_frame = self.lookup_or_allocate(pml4_address, page_addr);

            let frame_start_offset = chunk_start % 4096;
            let frame_end_offset = chunk_end % 4096;

            let dest_slice = &mut self.get_frame_mut(backing_frame)[frame_start_offset..(frame_end_offset + 1)];
            let src_slice = &code[(chunk_start - base_vaddr)..(chunk_end - base_vaddr + 1)];
            //println!("dest ptr: {:p} len: {}", dest_slice.as_ptr(), dest_slice.len());
            //println!("dest {:x?}", dest_slice);
            //println!("src ptr: {:p} len: {}", src_slice.as_ptr(), src_slice.len());
            //println!("src {:x?}", src_slice);
            dest_slice.copy_from_slice(src_slice);

            i = chunk_end + 1;
        }
    }

    /// Return the backing memory
    pub fn consume(self) -> MmapMut {
        self.backing
    }

    /// Return an unused frame
    fn next(&mut self) -> u64 {
        self.free.pop().expect("Out of frames")
    }

    /// Peek at the next unused frame
    fn peek(&self) -> u64 {
        *self.free.last().expect("Out of frames")
    }

    /// Construct a page table mapping the given pages linearly starting from the given virtual
    /// base address, returning the address of the PML4
    pub fn create_map(&mut self, pages: &[u64], vaddr: u64) -> (usize, Vec<u64>) {
        assert_eq!(vaddr % 4096, 0, "vaddr must be a multiple of 4096");
        let mut pages = pages.to_vec();

        let pml4_frame_num = self.create_pml4();
        let pml4_address = pml4_frame_num as usize * 4096;
        pages.push(pml4_frame_num);

        //println!("{:?}: {:?}", pml4_address , pml4_frame_num);
        let mut pt_pages = self.map_multiple(pml4_address, &pages, vaddr);
        pt_pages.push(pml4_frame_num);

        (pml4_address as usize, pt_pages)
    }

    /// Construct a pml4, returning its frame number
    pub fn create_pml4(&mut self) -> u64 {
        let pml4_frame_num = self.next();
        let pml4_address = pml4_frame_num as usize * 4096;
        //pages.push(pml4_frame as u64/4096);
        let pml4 = self.pml4_as_mut(pml4_address);
        std::mem::replace(pml4,[PML4Entry(0); 512]);
        pml4_frame_num
    }

    /// Lookup the frame for a given virtual address in the page tables anchored at `pml4_address`
    fn lookup(&self, pml4_address: usize, vaddr: usize) -> Option<usize> {
        //println!("Looking up {:x} in table at {:x}", vaddr, pml4_address);
        let pml4 = self.pml4_as_ref(pml4_address);
        let pml4_entry = pml4[pml4_index(vaddr.into())];
        if !pml4_entry.is_present() { return None } 
        let pdpt_address = pml4_entry.address();
        let pdpt = self.pdpt_as_ref(pdpt_address.into());
        let pdpt_entry = pdpt[pdpt_index(vaddr.into())];
        if !pdpt_entry.is_present() { return None }
        let pd_address = pdpt_entry.address();
        let pd = self.pd_as_ref(pd_address.into());
        let pd_entry = pd[pd_index(vaddr.into())];
        if !pd_entry.is_present() { return None }
        let pt_address = pd_entry.address();
        let pt = self.pt_as_ref(pt_address.into());
        let pt_entry = pt[pt_index(vaddr.into())];
        if pt_entry.is_present() { 
            Some(pt_entry.address().into())
        } else {
            None
        }
    }

    pub fn lookup_page(&self, pml4_address: usize, vaddr: usize) -> Option<&[u8]> {
        self.lookup(pml4_address, vaddr).map(|p|&self.backing[p..(p + 4096)])
    }

    pub fn get_frame(&self, frame_addr: usize) -> &[u8] {
        assert!(frame_addr % 4096 == 0);
        &self.backing[frame_addr..(frame_addr + 4096)]
    }

    pub fn get_frame_mut(&mut self, frame_addr: usize) -> &mut [u8] {
        assert!(frame_addr % 4096 == 0);
        &mut self.backing[frame_addr..(frame_addr + 4096)]
    }

    /// Lookup the frame for an address or allocate one
    pub fn lookup_or_allocate(&mut self, pml4_address: usize, vaddr: usize) -> usize {
        self.lookup(pml4_address, vaddr).unwrap_or_else(||{
            let phys = self.next() * 4096;
            self.map(pml4_address, phys, vaddr as u64);
            phys as usize
        })
    }

    // these methods are probably unnecesary, but they quarantine the unsafe
    fn pml4_as_ref<'a>(&'a self, pml4_address: usize) -> &'a PML4 {
        assert!(pml4_address % 4096 == 0);
            let (pre, pml4, post): (_, &[_], _) = unsafe { self.backing[(pml4_address..pml4_address + 4096)].align_to() };
            assert_eq!(pre.len(), 0);
            assert_eq!(post.len(), 0);
            &pml4[0]
    }

    fn pml4_as_mut<'a>(&'a mut self, pml4_address: usize) -> &'a mut PML4 {
        assert!(pml4_address % 4096 == 0);
            let (pre, pml4, post): (_, &mut [_], _) = unsafe { self.backing[(pml4_address..pml4_address + 4096)].align_to_mut() };
            assert_eq!(pre.len(), 0);
            assert_eq!(post.len(), 0);
            &mut pml4[0]
    }

    fn pdpt_as_ref<'a>(&'a self, pdpt_address: usize) -> &'a PDPT {
        assert!(pdpt_address % 4096 == 0);
            let (pre, pt, post) = unsafe { self.backing[(pdpt_address..pdpt_address + 4096)].align_to() };
            assert_eq!(pre.len(), 0);
            assert_eq!(post.len(), 0);
            &pt[0]
    }

    fn pdpt_as_mut<'a>(&'a mut self, pdpt_address: usize) -> &'a mut PDPT {
        assert!(pdpt_address % 4096 == 0);
            let (pre, pt, post) = unsafe { self.backing[(pdpt_address..pdpt_address + 4096)].align_to_mut() };
            assert_eq!(pre.len(), 0);
            assert_eq!(post.len(), 0);
            &mut pt[0]
    }

    fn pd_as_ref<'a>(&'a self, pd_address: usize) -> &'a PD {
        assert!(pd_address % 4096 == 0);
            let (pre, pt, post) = unsafe { self.backing[(pd_address..pd_address + 4096)].align_to() };
            assert_eq!(pre.len(), 0);
            assert_eq!(post.len(), 0);
            &pt[0]
    }

    fn pd_as_mut<'a>(&'a mut self, pd_address: usize) -> &'a mut PD {
        assert!(pd_address % 4096 == 0);
            let (pre, pt, post) = unsafe { self.backing[(pd_address..pd_address + 4096)].align_to_mut() };
            assert_eq!(pre.len(), 0);
            assert_eq!(post.len(), 0);
            &mut pt[0]
    }

    fn pt_as_ref<'a>(&'a self, pt_address: usize) -> &'a PT {
        assert!(pt_address % 4096 == 0);
            let (pre, pt, post) = unsafe { self.backing[(pt_address..pt_address + 4096)].align_to() };
            assert_eq!(pre.len(), 0);
            assert_eq!(post.len(), 0);
            &pt[0]
    }

    fn pt_as_mut<'a>(&'a mut self, pt_address: usize) -> &'a mut PT {
        assert!(pt_address % 4096 == 0);
            let (pre, pt, post) = unsafe { self.backing[(pt_address..pt_address + 4096)].align_to_mut() };
            assert_eq!(pre.len(), 0);
            assert_eq!(post.len(), 0);
            &mut pt[0]
    }

    /// Map the given pages, returning the addresses of the new page tables allocated
    fn map_multiple(&mut self, pml4: usize, pages: &[u64], vaddr: u64) -> Vec<u64> {
        let mut pt_pages = vec![];
        for (i, page) in pages.iter().enumerate() {
            pt_pages.append(&mut self.map(pml4, page * 4096, vaddr + i as u64 * 4096));
        }
        pt_pages
    }

    /// Map the given virtual address to the given physical address, returning the addresses of the
    /// page tables allocated
    pub fn map(&mut self, pml4_addr: usize, phys_address: u64, virt_address: u64) -> Vec<u64> {
        assert_eq!(phys_address % 4096, 0, "physical address must be a multiple of 4096");
        assert_eq!(virt_address % 4096, 0, "virtual address must be a multiple of 4096");
        assert_eq!(pml4_addr % 4096, 0, "pml4 address must be a multiple of 4096");
        //println!("Mapping {:x} to {:x} in table at {:x}", virt_address, phys_address, pml4_addr);

        let mut pt_pages = vec![];

        let mut next = self.peek();

        // BIG BRAIN COPY PASTE
        let pdpt_frame = {
            let pml4 = self.pml4_as_mut(pml4_addr);

            // Find the corresponding PDPT, allocating a new one if necessary
            if pml4[pml4_index(VAddr::from_u64(virt_address))].is_present() {
                pml4[pml4_index(VAddr::from_u64(virt_address))].address().0 as usize
            } else {
                let pdpt_frame_num = next;
                let pdpt_frame = next as usize * 4096;
                pml4[pml4_index(VAddr::from_u64(virt_address))] = PML4Entry::new(pdpt_frame.into(), PML4Flags::P | PML4Flags::RW);
                // for (i, x) in pml4.iter().enumerate() {
                //     if x.is_present() {
                //         println!("{}: {:?}", i, x);
                //     }
                // }
                let pdpt = self.pdpt_as_mut(pdpt_frame);
                // initialize PDPT with all zeroes
                std::mem::replace(pdpt,[PDPTEntry(0); 512]);

                pt_pages.push(pdpt_frame_num);
                self.next();
                next = self.peek();
                pdpt_frame
            }
        };

        let pd_frame = {
            let pdpt = self.pdpt_as_mut(pdpt_frame);

            // Find the corresponding PD, allocating a new one if necessary
            if pdpt[pdpt_index(VAddr::from_u64(virt_address))].is_present() {
                pdpt[pdpt_index(VAddr::from_u64(virt_address))].address().0 as usize
            } else {
                let pd_frame_num = next;
                let pd_frame = next as usize * 4096;
                pdpt[pdpt_index(VAddr::from_u64(virt_address))] = PDPTEntry::new(pd_frame.into(), PDPTFlags::P | PDPTFlags::RW);

                let pd = self.pd_as_mut(pd_frame);
                // initialize PD with all zeroes
                std::mem::replace(pd,[PDEntry(0); 512]);

                pt_pages.push(pd_frame_num);
                self.next();
                next = self.peek();
                pd_frame
            }
        };

        let pt_frame = {
            let pd = self.pd_as_mut(pd_frame);
            //
            // Find the corresponding PT, allocating a new one if necessary
            if pd[pd_index(VAddr::from_u64(virt_address))].is_present() {
                pd[pd_index(VAddr::from_u64(virt_address))].address().0 as usize
            } else {
                let pt_frame_num = next;
                let pt_frame = next as usize * 4096;
                pd[pd_index(VAddr::from_u64(virt_address))] = PDEntry::new(pt_frame.into(), PDFlags::P | PDFlags::RW);

                let pt = self.pt_as_mut(pt_frame);
                // initialize PT with all zeroes
                std::mem::replace(pt,[PTEntry(0); 512]);

                pt_pages.push(pt_frame_num);
                self.next();
                // next = self.peek();
                pt_frame
            }
        };
        // END BIG BRAIN

        let pt = self.pt_as_mut(pt_frame);
        //dbg!(phys_address);
        pt[pt_index(VAddr::from_u64(virt_address))] = PTEntry::new(phys_address.into(), PTFlags::P | PTFlags::RW);

        pt_pages
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
        res.map_err(|e| std::io::Error::from_raw_os_error(e.errno())).unwrap();

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

    pub fn run_core(&self, core_id: u8, chan: channel::Sender<HyperMessage>) -> Result<(), ()> {
        loop {
            match self.cores[core_id as usize].run()? {
                VcpuExit::Hlt => {
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
                                    chan.send(HyperMessage::Print(s.to_owned()));
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
                VcpuExit::Shutdown => {
                    let regs = self.cores[core_id as usize].vcpu.get_regs().unwrap();
                    println!("Shutting down {:?}", regs);
                    break
                }
                e => {
                    panic!("unexpected vcpu exit {:?}", e);
                }
            }
        }
        Ok(())
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
    pub fn load(&mut self, executable: &[u8]) {
        let elf = Elf::parse(&executable).unwrap();

        let cr3 = self.mem.create_pml4() * 4096;
        for h in elf.program_headers {
            if h.p_type != PT_LOAD {
                continue
            }
            let mut code = vec![0; h.p_memsz as usize];
            if h.p_filesz > 0 {
                code.copy_from_slice(&executable[h.p_offset as usize..(h.p_offset as usize + h.p_filesz as usize)]);
            }
            self.mem.load2(cr3 as usize, &code, h.p_vaddr as usize);
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
        self.programs.push(prog)
    }

    /// Run all programs
    pub fn run(mut self) {
        thread::spawn(move || {
            self.run_threads()
        }).join();
    }
    fn run_threads(&mut self) {

        let num_cores = self.programs.iter().map(|p|p.core_count() as usize).sum();

        let (send, recv) = channel::bounded::<HyperMessage>(num_cores);

        let barrier = Arc::new(Barrier::new(num_cores));
        crossbeam::scope(|scope| {
            self.programs.iter().flat_map(|p| {
                (0..p.core_count()).map( move |i|{
                    (p, i)
                })
            }).for_each(|(p, i)| {
                use std::os::unix::io::AsRawFd;
                let s = send.clone();
                let b = barrier.clone();
                scope.spawn(move |_|{
                    b.wait();
                    p.run_core(i, s)
                });
            });
            // This way the channel closes
            drop(send);
            loop {
                match recv.recv() {
                    Ok(HyperMessage::Print(s)) => {
                        print!("{}", s);
                    }
                    Err(e) => {
                        println!("{:?}", e);
                        break
                    }
                }
            }
        }).unwrap();
    }
}

enum HyperMessage {
    Print(String)
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

    pub fn run(&self) -> Result<VcpuExit, ()> {
        self.vcpu.run().map_err(|_|())
    }
}
