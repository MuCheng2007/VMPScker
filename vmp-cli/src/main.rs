use clap::{Parser, Subcommand};
use tracing::{info, error};
use std::path::PathBuf;

mod marker_cmd;
mod vm_test;
use marker_cmd::{MarkerArgs, MarkerCommands, handle_marker_command};
use vm_test::run_test;

#[derive(Parser, Debug)]
#[command(name = "vmp")]
#[command(about = "VMProtect - Software protection system")]
struct Args {
    #[command(subcommand)]
    command: Commands,

    #[arg(short = 'd', long = "debug", help = "Debug mode")]
    debug: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Protect a PE file with VM
    #[command(name = "protect")]
    Protect {
        /// Input PE file
        #[arg(short = 'i', long = "input")]
        input: PathBuf,

        /// Output PE file
        #[arg(short = 'o', long = "output")]
        output: PathBuf,

        /// Protection mode (32 or 64)
        #[arg(short = 'm', long = "mode", default_value = "64")]
        mode: String,

        /// Section to protect (e.g., .text)
        #[arg(short = 's', long = "section", default_value = ".text")]
        section: String,

        /// Disable VM code encryption
        #[arg(long = "no-encrypt")]
        no_encrypt: bool,

        /// Add anti-debug
        #[arg(long = "anti-debug")]
        anti_debug: bool,
    },

    /// Analyze a PE file
    #[command(name = "analyze")]
    Analyze {
        /// Input PE file
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
    },

    /// VMP Marker detection commands
    #[command(name = "marker")]
    Marker(MarkerArgs),

    /// Test VM conversion
    #[command(name = "test-vm")]
    TestVm {
        /// Input PE file
        #[arg(short = 'i', long = "input")]
        input: PathBuf,

        /// Architecture mode (32 or 64)
        #[arg(short = 'm', long = "mode", default_value = "64")]
        mode: String,
    },
}

fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    match args.command {
        Commands::Protect { input, output, mode, section, no_encrypt, anti_debug } => {
            info!("Protecting file: {:?} -> {:?}", input, output);
            
            if let Err(e) = protect_file(input, output, mode, section, !no_encrypt, anti_debug) {
                error!("Protection failed: {:?}", e);
                std::process::exit(1);
            }
            
            info!("Protection completed successfully!");
        }
        Commands::Analyze { input } => {
            info!("Analyzing file: {:?}", input);
            
            if let Err(e) = analyze_file(input) {
                error!("Analysis failed: {:?}", e);
                std::process::exit(1);
            }
        }
        Commands::Marker(args) => {
            if let Err(e) = handle_marker_command(args) {
                error!("Marker detection failed: {:?}", e);
                std::process::exit(1);
            }
        }
        Commands::TestVm { input, mode } => {
            info!("Testing VM conversion: {:?}", input);
            
            if let Err(e) = run_test(input, mode) {
                error!("VM conversion test failed: {:?}", e);
                std::process::exit(1);
            }
        }
    }
}

fn protect_file(
    input: PathBuf,
    output: PathBuf,
    mode: String,
    section: String,
    encrypt: bool,
    anti_debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use vmp_core::protector::{VmpProtector, ProtectConfig, ProtectRange};
    use vmp_core::intel::DisassemblyMode;

    // 解析模式
    let disasm_mode = match mode.as_str() {
        "32" => DisassemblyMode::Mode32,
        "64" => DisassemblyMode::Mode64,
        _ => {
            error!("Invalid mode: {}. Use '32' or '64'", mode);
            return Err("Invalid mode".into());
        }
    };

    // 创建配置
    let config = ProtectConfig {
        mode: disasm_mode,
        encrypt_vm_code: encrypt,
        anti_debug,
        ..Default::default()
    };

    // 创建保护器
    let protector = VmpProtector::with_config(config);

    // 保护范围
    let ranges = vec![ProtectRange::FullSection(section)];

    // 执行保护
    info!("Starting protection process...");
    let result = protector.protect_file(&input, &output, ranges)?;

    info!("Protection result:");
    info!("  - Original entry: 0x{:X}", result.original_entry);
    info!("  - VM entry: 0x{:X}", result.vm_entry);
    info!("  - VM code size: {} bytes", result.vm_code_size);
    info!("  - Protected instructions: {}", result.protected_instructions);
    info!("  - VM instructions: {}", result.vm_instructions);

    Ok(())
}

fn analyze_file(input: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use vmp_core::pe::file::PeFile;

    info!("Loading PE file: {:?}", input);
    let pe_file = PeFile::load(&input)?;

    if let Some(pe) = pe_file.pe() {
        info!("PE Analysis:");
        info!("  - Number of sections: {}", pe.sections.len());
        
        info!("\nSections:");
        for (i, section) in pe.sections.iter().enumerate() {
            let name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string();
            info!("  [{}] {} - RVA: 0x{:X}, Size: 0x{:X}",
                i, name, section.virtual_address, section.virtual_size);
        }
    }

    Ok(())
}
