use std::thread;
use std::sync::{Arc,Barrier};
use std::fs::File;
use std::io::Read;

use goblin::elf::Elf;

use kvm_ioctls::{Kvm, VmFd, VcpuFd, VcpuExit};
use memmap::{MmapOptions,MmapMut};
use rand::seq::SliceRandom;
use rand::thread_rng;
use x86::bits64::paging::*;

fn main() {

    let mem_size = 0x40000;
    let mut mem = MemAlloc::new(mem_size);

    let mut file1 = vec!();
    File::open("core1").unwrap().read_to_end(&mut file1).unwrap();

    let elf1 = Elf::parse(&file1).unwrap();

    println!("{:#?}", elf1);

    let mut file2 = vec!();
    File::open("core2").unwrap().read_to_end(&mut file2).unwrap();

    let elf2 = Elf::parse(&file2).unwrap();

    println!("{:#?}", elf2);

    let x86_code = [
        0xb8, 0x40, 0x00, 0x00, 0x00, /* mov rax, 64 */
        0xf4,             /* hlt */
    ];

    let x86_code_2 = [
        0xb8, 0x80, 0x00, 0x00, 0x00, /* mov rax, 128 */
        0xf4,             /* hlt */
    ];

    //// copy code into vm memory
    //for (i, x) in x86_code.iter().enumerate() {
    //    mem[i] = *x
    //}

    let cr3 = mem.load(&x86_code, 0x1000);

    let cr3_2 = mem.load(&x86_code_2, 0x1000);

    let mut vm = VM::new(mem.consume());
    let core1 = vm.new_core();
    let core2 = vm.new_core();

    let barrier = Arc::new(Barrier::new(2));
    let b1 = barrier.clone();
    let h1 = thread::spawn(move ||{
        barrier.wait();
        core1.run64bit(0x1000, cr3)
    });
    let h2 = thread::spawn(move ||{
        b1.wait();
        core2.run64bit(0x1000, cr3_2)
    });
    h1.join();
    h2.join();
    //run64bit(mem.consume(), 0x1000, cr3);

    println!("Hello, world!");
}

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
    /// Load the provided code into memory, creating a page table with it allocated at the given
    /// `vaddr`, returning the address of the top level page table
    pub fn load(&mut self, code: &[u8], vaddr: u64) -> u64 {
        assert_eq!(vaddr % 4096, 0, "vaddr must be a multiple of 4096");
        let mut pages = vec![];
        let mut count = 0;
        while count < code.len() {
            let page_num = self.next();
            let page = page_num as usize * 4096;
            pages.push(page_num);

            let stride = if code.len() - count >= 4096 { 4096 } else { code.len() - count };
            let target = &mut self.backing[(page..page + stride)];
            target.copy_from_slice(&code[count..count+stride]);

            count += 4096
        }

        self.create_map(&pages, vaddr) as u64
    }

    /// Return the backing memory
    pub fn consume(self) -> MmapMut {
        self.backing
    }

    /// Return an unused page
    fn next(&mut self) -> u64 {
        self.free.pop().expect("Out of pages")
    }

    /// Peek at the next unused page
    fn peek(&self) -> u64 {
        *self.free.last().expect("Out of pages")
    }

    /// Construct a page table mapping the given pages linearly starting from the given virtual
    /// base address, returning the address of the PML4
    pub fn create_map(&mut self, pages: &[u64], mut vaddr: u64) -> usize {
        assert_eq!(vaddr % 4096, 0, "vaddr must be a multiple of 4096");
        let mut pages = pages.to_vec();

        let pml4_frame_num = self.create_pml4();
        let pml4_address = pml4_frame_num as usize * 4096;
        pages.push(pml4_frame_num);

        println!("{:?}: {:?}", pml4_address , pml4_frame_num);
        let pt_pages = self.map_multiple(pml4_address, &pages, vaddr);

        pml4_address as usize
    }

    /// Construct a pml4
    pub fn create_pml4(&mut self) -> u64 {
        let pml4_frame_num = self.next();
        let pml4_address = pml4_frame_num as usize * 4096;
        //pages.push(pml4_frame as u64/4096);
        let pml4 = self.pml4_as_mut(pml4_address);
        std::mem::replace(pml4,[PML4Entry(0); 512]);
        pml4_frame_num
    }

    fn pml4_as_mut<'a>(&'a mut self, pml4_address: usize) -> &'a mut PML4 {
            let (pre, pml4, post): (_, &mut [_], _) = unsafe { self.backing[(pml4_address..pml4_address + 4096)].align_to_mut() };
            assert_eq!(pre.len(), 0);
            assert_eq!(post.len(), 0);
            &mut pml4[0]
    }

    fn pdpt_as_mut<'a>(&'a mut self, pdpt_address: usize) -> &'a mut PDPT {
            let (pre, pt, post) = unsafe { self.backing[(pdpt_address..pdpt_address + 4096)].align_to_mut() };
            assert_eq!(pre.len(), 0);
            assert_eq!(post.len(), 0);
            &mut pt[0]
    }

    fn pd_as_mut<'a>(&'a mut self, pd_address: usize) -> &'a mut PD {
            let (pre, pt, post) = unsafe { self.backing[(pd_address..pd_address + 4096)].align_to_mut() };
            assert_eq!(pre.len(), 0);
            assert_eq!(post.len(), 0);
            &mut pt[0]
    }

    fn pt_as_mut<'a>(&'a mut self, pt_address: usize) -> &'a mut PT {
            let (pre, pt, post) = unsafe { self.backing[(pt_address..pt_address + 4096)].align_to_mut() };
            assert_eq!(pre.len(), 0);
            assert_eq!(post.len(), 0);
            &mut pt[0]
    }

    /// Map the given pages, returning the addresses of the new pages allocated
    fn map_multiple(&mut self, pml4: usize, pages: &[u64], mut vaddr: u64) -> Vec<u64> {
        let mut pt_pages = vec![];
        for (i, page) in pages.iter().enumerate() {
            pt_pages.append(&mut self.map(pml4, page * 4096, vaddr + i as u64 * 4096))
        }
        pt_pages
    }

    /// Map the given virtual address to the given physical address
    fn map(&mut self, pml4_addr: usize, phys_address: u64, virt_address: u64) -> Vec<u64> {
        assert_eq!(phys_address % 4096, 0, "physical address must be a multiple of 4096");
        assert_eq!(virt_address % 4096, 0, "virtual address must be a multiple of 4096");
        assert_eq!(pml4_addr % 4096, 0, "pml4 address must be a multiple of 4096");

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
                for (i, x) in pml4.iter().enumerate() {
                    if x.is_present() {
                        println!("{}: {:?}", i, x);
                    }
                }
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
                next = self.peek();
                pt_frame
            }
        };
        // END BIG BRAIN

        let pt = self.pt_as_mut(pt_frame);
        dbg!(phys_address);
        pt[pt_index(VAddr::from_u64(virt_address))] = PTEntry::new(phys_address.into(), PTFlags::P | PTFlags::RW);

        pt_pages
    }
}

/// A VM along with the memory used to back it
pub struct VM {
    mem: MmapMut,
    vmfd: VmFd,
    next_vcpu_id: u8
}

impl VM {
    /// Make a new VM using the given memory
    pub fn new(mut mem: MmapMut) -> Self {
        let kvm = Kvm::new().unwrap();

        let vm = kvm.create_vm().unwrap();

        let mem_region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: mem.len() as u64,
            userspace_addr: (&mut mem[0] as *mut u8) as u64,
            flags: 0
        };
        unsafe { vm.set_user_memory_region(mem_region).unwrap() };
        Self {
            mem: mem,
            vmfd: vm,
            next_vcpu_id: 0
        }
    }
    /// Create a new core for our VM
    pub fn new_core(&mut self) -> VMCore {
        let c = VMCore::new(self.vmfd.create_vcpu(self.next_vcpu_id).unwrap());
        self.next_vcpu_id += 1;
        c
    }
}

/// One core of our virtual machine
pub struct VMCore {
    vcpu: VcpuFd
}

impl VMCore {
    fn new(vcpu: VcpuFd) -> Self {
        let mut vcpu_sregs = vcpu.get_sregs().unwrap();
        vcpu_sregs.cr4 = 0b10100000;
        //vcpu_sregs.cr3 = cr3; // We set cr3 later
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

    /// Run some 64 bit mode idgaf
    pub fn run64bit(&self, entry: u64, cr3: u64) {
        let mut vcpu_sregs = self.vcpu.get_sregs().unwrap();
        vcpu_sregs.cr3 = cr3; // TODO: point at page tables
        self.vcpu.set_sregs(&vcpu_sregs).unwrap();

        let mut vcpu_regs = self.vcpu.get_regs().unwrap();
        vcpu_regs.rip = entry;
        self.vcpu.set_regs(&vcpu_regs).unwrap();

        loop {
            match self.vcpu.run().expect("run failed") {
                VcpuExit::Hlt => {
                    println!("Halt");
                    break;
                }
                exit_reason => {
                    println!("Unexpected exit reason: {:?}", exit_reason);
                    dbg!(self.vcpu.get_sregs());
                    break;
                }
            }
        }

        let vcpu_regs = self.vcpu.get_regs().unwrap();
        println!("{:?}", vcpu_regs);
    }
}
