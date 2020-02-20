use std::fs::File;
use std::io::Read;
use std::time::Duration;

use clap::{App,Arg};

use x64wars::{MemAlloc, Arena, ArenaCommand, ArenaMessage};

fn main() {
    let matches = App::new("x64 Wars")
        .version("0.1")
        .arg(Arg::with_name("program")
            .index(1)
            .multiple(true)
            .required(true)
        )
        .arg(Arg::with_name("mem_size")
            .short("m")
            .takes_value(true)
            .default_value("0x400000")
        )
        .arg(Arg::with_name("time")
            .short("t")
            .takes_value(true)
            .help("How long to wait (in ms) for programs to finish, if not present wait forever")
        )
        .arg(Arg::with_name("repeat")
            .short("r")
            .takes_value(true)
            .default_value("1")
        ).get_matches();

    let programs = matches.values_of_os("program").unwrap();

    let mem_size = usize::from_str_radix(matches.value_of("mem_size").unwrap().trim_start_matches("0x"), 16).expect("Unable to parse mem_size");

    let r: usize = str::parse(matches.value_of("repeat").unwrap()).expect("invalid r value");
    let t: Option<u64> = matches.value_of("time").map(|s|str::parse(s).expect("invalid r value"));
    if mem_size % 4096 != 0 {
        println!("mem_size must be a multiple of 4096");
        return
    }
    let mem = MemAlloc::new(mem_size);

    let mut arena = Arena::new(mem);

    println!("Loading {} programs", programs.len() * r);

    for (pi, p) in programs.enumerate() {
        for i in 0..r {
            let mut file = vec!();
            File::open(p).unwrap().read_to_end(&mut file).unwrap();
            let id = arena.load(&file);
            println!("Loaded program {} copy {} with id: {}", pi, i, id);
        }
    }

    println!("Programs loaded!");

    let h = arena.run();

    let timeout = t.map(|t| Duration::from_millis(t));

    println!("{:?}", h.wait(timeout).unwrap().1.last());
}
