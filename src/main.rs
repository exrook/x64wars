use kvm_ioctls::{Kvm, VmFd, VcpuFd, VcpuExit};
use memmap::{MmapOptions,MmapMut};
use rand::seq::SliceRandom;
use rand::thread_rng;
use x86::bits64::paging::*;

fn main() {

    let mem_size = 0x40000;
    let mut mem = MemAlloc::new(mem_size);

    let x86_code = [
        0xb8, 0x40, 0x00, 0x00, 0x00, 0xf4, /* mov rax, 64 */
        0xf4,             /* hlt */
    ];

    //// copy code into vm memory
    //for (i, x) in x86_code.iter().enumerate() {
    //    mem[i] = *x
    //}

    let cr3 = mem.load(&x86_code, 0x1000);

    run64bit(mem.consume(), 0x1000, cr3);

    println!("Hello, world!");
}

#[derive(Debug)]
struct MemAlloc {
    backing: MmapMut,
    free: Vec<u64>
}

impl MemAlloc {
    pub fn new(size: usize) -> Self {
        assert_eq!(size % 4096, 0, "size must be a multiple of 4096");
        let mut free: Vec<_> = (0..(size as u64/4096)).collect();
        free.shuffle(&mut thread_rng());
        Self {
            backing: MmapOptions::new().len(size).map_anon().unwrap(),
            free
        }
    }
    // Load the provided code into memory, creating a page table with it allocated at the given
    // `vaddr`, returning the address of the top level page table
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
        self.map(&pages, vaddr)
    }

    /// Return the backing memory
    pub fn consume(self) -> MmapMut {
        self.backing
    }

    /// Return an unused page
    fn next(&mut self) -> u64 {
        self.free.pop().expect("Out of pages")
    }

    /// Construct a page table mapping the given pages linearly starting from the given virtual
    /// base address, returning the address of the PML4
    fn map(&mut self, pages: &[u64], mut vaddr: u64) -> u64 {
        assert_eq!(vaddr % 4096, 0, "vaddr must be a multiple of 4096");
        let mut pages = pages.to_vec();

        let pml4_frame_num = self.next();
        let pml4_frame = pml4_frame_num as usize * 4096;
        pages.push(pml4_frame as u64/4096);
        {
            let (pre, pml4, post): (_, &mut [PML4], _) = unsafe { self.backing[(pml4_frame..pml4_frame + 4096)].align_to_mut() };
            assert_eq!(pre.len(), 0);
            assert_eq!(post.len(), 0);
            let pml4 = &mut pml4[0];
            // initialize PML4 with all zeroes
            std::mem::replace(pml4,[PML4Entry(0); 512]);
        }

        let mut idx = 0;
        let mut next = self.next();
        while idx < pages.len() {
            let phys_page_num = pages[idx];
            let phys_page = phys_page_num * 4096;
            // BIG BRAIN COPY PASTE
            let pdpt_frame = {
                let (pre, pml4, post): (_, &mut [PML4], _) = unsafe { self.backing[(pml4_frame..pml4_frame + 4096)].align_to_mut() };
                assert_eq!(pre.len(), 0);
                assert_eq!(post.len(), 0);
                let pml4 = &mut pml4[0];

                // Find the corresponding PDPT, allocating a new one if necessary
                if pml4[pml4_index(VAddr::from_u64(vaddr))].is_present() {
                    pml4[pml4_index(VAddr::from_u64(vaddr))].address().0 as usize
                } else {
                    let pdpt_frame_num = next;
                    let pdpt_frame = next as usize * 4096;
                    pml4[pml4_index(VAddr::from_u64(vaddr))] = PML4Entry::new(pdpt_frame.into(), PML4Flags::P | PML4Flags::RW);
                    for (i, x) in pml4.iter().enumerate() {
                        if x.is_present() {
                            println!("{}: {:?}", i, x);
                        }
                    }
                    {
                        let (pre, pdpt, post): (_, &mut [PDPT], _) = unsafe { self.backing[(pdpt_frame..pdpt_frame + 4096)].align_to_mut() };
                        assert_eq!(pre.len(), 0);
                        assert_eq!(post.len(), 0);
                        let pdpt = &mut pdpt[0];
                        // initialize PDPT with all zeroes
                        std::mem::replace(pdpt,[PDPTEntry(0); 512]);
                    }
                    pages.push(pdpt_frame_num);
                    next = self.next();
                    pdpt_frame
                }
            };

            let pd_frame = {
                let (pre, pdpt, post): (_, &mut [PDPT], _) = unsafe { self.backing[(pdpt_frame..pdpt_frame + 4096)].align_to_mut() };
                assert_eq!(pre.len(), 0);
                assert_eq!(post.len(), 0);
                let pdpt = &mut pdpt[0];

                // Find the corresponding PD, allocating a new one if necessary
                if pdpt[pdpt_index(VAddr::from_u64(vaddr))].is_present() {
                    pdpt[pdpt_index(VAddr::from_u64(vaddr))].address().0 as usize
                } else {
                    let pd_frame_num = next;
                    let pd_frame = next as usize * 4096;
                    pdpt[pdpt_index(VAddr::from_u64(vaddr))] = PDPTEntry::new(pd_frame.into(), PDPTFlags::P | PDPTFlags::RW);
                    {
                        let (pre, pd, post): (_, &mut [PD], _) = unsafe { self.backing[(pd_frame..pd_frame + 4096)].align_to_mut() };
                        assert_eq!(pre.len(), 0);
                        assert_eq!(post.len(), 0);
                        let pd = &mut pd[0];
                        // initialize PD with all zeroes
                        std::mem::replace(pd,[PDEntry(0); 512]);
                    }
                    pages.push(pd_frame_num);
                    next = self.next();
                    pd_frame
                }
            };

            let pt_frame = {
                let (pre, pd, post): (_, &mut [PD], _) = unsafe { self.backing[(pd_frame..pd_frame + 4096)].align_to_mut() };
                assert_eq!(pre.len(), 0);
                assert_eq!(post.len(), 0);
                let pd = &mut pd[0];

                // Find the corresponding PT, allocating a new one if necessary
                if pd[pd_index(VAddr::from_u64(vaddr))].is_present() {
                    pd[pd_index(VAddr::from_u64(vaddr))].address().0 as usize
                } else {
                    let pt_frame_num = next;
                    let pt_frame = next as usize * 4096;
                    pd[pd_index(VAddr::from_u64(vaddr))] = PDEntry::new(pt_frame.into(), PDFlags::P | PDFlags::RW);
                    {
                        let (pre, pt, post): (_, &mut [PT], _) = unsafe { self.backing[(pt_frame..pt_frame + 4096)].align_to_mut() };
                        assert_eq!(pre.len(), 0);
                        assert_eq!(post.len(), 0);
                        let pt = &mut pt[0];
                        // initialize PT with all zeroes
                        std::mem::replace(pt,[PTEntry(0); 512]);
                    }
                    pages.push(pt_frame_num);
                    next = self.next();
                    pt_frame
                }
            };
            // END BIG BRAIN

            {
                let (pre, pt, post): (_, &mut [PT], _) = unsafe { self.backing[(pt_frame..pt_frame + 4096)].align_to_mut() };
                assert_eq!(pre.len(), 0);
                assert_eq!(post.len(), 0);
                let pt = &mut pt[0];
                // Create the mapping
                dbg!(phys_page);
                pt[pt_index(VAddr::from_u64(vaddr))] = PTEntry::new(phys_page.into(), PTFlags::P | PTFlags::RW);
            }

            idx += 1;
            vaddr += 4096;
        }
        pml4_frame as u64
    }
}

fn run64bit(mut mem: MmapMut, entry: u64, cr3: u64) {
    let kvm = Kvm::new().unwrap();

    let vm = kvm.create_vm().unwrap();

    //let guest_addr = 0x1000;
    let guest_addr = entry;
    let mem_region = kvm_bindings::kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: mem.len() as u64,
        userspace_addr: (&mut mem[0] as *mut u8) as u64,
        flags: 0
    };
    unsafe { vm.set_user_memory_region(mem_region).unwrap() }

    let vcpu = vm.create_vcpu(0).unwrap();

    let mut vcpu_sregs = vcpu.get_sregs().unwrap();
    vcpu_sregs.cr4 = 0b10100000;
    vcpu_sregs.cr3 = cr3; // TODO: point at page tables
    vcpu_sregs.efer |= 0x00000500;
    vcpu_sregs.cr0 |= 0x80000001;

    vcpu_sregs.cs.db = 0;
    vcpu_sregs.cs.l = 1;
    vcpu_sregs.cs.present = 1;
    vcpu_sregs.cs.dpl = 0;
    vcpu_sregs.cs.type_ = 0b1000;
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.limit = 0;

    vcpu.set_sregs(&vcpu_sregs).unwrap();

    let mut vcpu_regs = vcpu.get_regs().unwrap();
    vcpu_regs.rip = guest_addr;
    vcpu.set_regs(&vcpu_regs).unwrap();

    loop {
        match vcpu.run().expect("run failed") {
            VcpuExit::Hlt => {
                println!("Halt");
                break;
            }
            exit_reason => {
                println!("Unexpected exit reason: {:?}", exit_reason);
                dbg!(vcpu.get_sregs());
                break;
            }
        }
    }

    let vcpu_regs = vcpu.get_regs().unwrap();
    println!("{:?}", vcpu_regs);
}
