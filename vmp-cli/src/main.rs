use clap::Parser;
use tracing::{info, error};

#[derive(Parser, Debug)]
#[command(name = "vmp")]
#[command(about = "VMProtect - Software protection system")]
struct Args {
    #[arg(short = 'p', long = "project", help = "Project file")]
    project_file: Option<String>,

    #[arg(short = 's', long = "script", help = "Script file")]
    script_file: Option<String>,

    #[arg(short = 'w', long = "watermark", help = "Watermark")]
    watermark: Option<String>,

    #[arg(short = 'l', long = "license", help = "License file")]
    license_file: Option<String>,

    #[arg(short = 'b', long = "build", help = "Build mode")]
    build_mode: Option<String>,

    #[arg(short = 'd', long = "debug", help = "Debug mode")]
    debug: bool,
}

fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    info!("VMProtect CLI started");

    if let Some(project) = args.project_file {
        info!("Loading project: {}", project);
    }

    if let Some(script) = args.script_file {
        info!("Loading script: {}", script);
    }
}
