use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Bpf;
//use aya_log::BpfLogger;
use clap::Parser;
//use log::info;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);

    let mut bpf = Bpf::load_file("/home/afredette/bpf/accept-all.o")?;
    let program: &mut SchedClassifier = bpf.program_mut("accept").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    let mut bpf = Bpf::load_file("/home/afredette/bpf/drop-icmp.o")?;
    let program: &mut SchedClassifier = bpf.program_mut("drop_icmp").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
