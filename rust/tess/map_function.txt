//! MapFunction 和 SDK 集成
//!
//! 提供导入函数与 SDK 函数的映射机制，支持 VMProtect SDK 标记的函数识别和处理。

use std::collections::HashMap;

/// API 类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ApiType {
    None = 0,
    MemoryRead = 1,
    MemoryWrite = 2,
    MemoryAlloc = 3,
    MemoryFree = 4,
    StringOp = 5,
    CryptoOp = 6,
    FileOp = 7,
    RegistryOp = 8,
    NetworkOp = 9,
    ProcessOp = 10,
    ThreadOp = 11,
    Synchronization = 12,
    DebugOp = 13,
    Virtualization = 14,
    AntiDebug = 15,
    Compression = 16,
    Hashing = 17,
    Encryption = 18,
    Decryption = 19,
    Random = 20,
    Time = 21,
    Environment = 22,
    SystemInfo = 23,
    ModuleOp = 24,
    ExceptionOp = 25,
    MemoryProtect = 26,
    Ipc = 27,
    ServiceOp = 28,
    UserOp = 29,
    SecurityOp = 30,
    TokenOp = 31,
    PrivilegeOp = 32,
    AuditOp = 33,
    EventLog = 34,
    Performance = 35,
    PowerOp = 36,
    DeviceOp = 37,
    DriverOp = 38,
    IoOp = 39,
    DmaOp = 40,
    InterruptOp = 41,
    ApicOp = 42,
    MmOp = 43,
    PnPOp = 44,
    WmiOp = 45,
    SetupOp = 46,
    ConfigOp = 47,
    UpdateOp = 48,
    BackupOp = 49,
    RestoreOp = 50,
    MigrationOp = 51,
    ReplicationOp = 52,
    ClusterOp = 53,
    StorageOp = 54,
    FsOp = 55,
    VolumeOp = 56,
    DiskOp = 57,
    PartitionOp = 58,
    MountOp = 59,
    ShareOp = 60,
    PrintOp = 61,
    JobOp = 62,
    TaskOp = 63,
    ScheduleOp = 64,
    TimerOp = 65,
    WaitOp = 66,
    SignalOp = 67,
    EventOp = 68,
    MutexOp = 69,
    SemaphoreOp = 70,
    CriticalSectionOp = 71,
    RwLockOp = 72,
    BarrierOp = 73,
    ConditionOp = 74,
    MonitorOp = 75,
    SpinLockOp = 76,
    AtomicOp = 77,
    TransactionOp = 78,
    ResourceOp = 79,
    HandleOp = 80,
    ObjectOp = 81,
    DirectoryOp = 82,
    SymbolicLinkOp = 83,
    JunctionOp = 84,
    ReparseOp = 85,
    StreamOp = 86,
    AlternateDataStreamOp = 87,
    ExtendedAttributeOp = 88,
    SparseFileOp = 89,
    CompressionOp = 90,
    EncryptionOp = 91,
    QuotaOp = 92,
    ObjectIdOp = 93,
    ReparsePointOp = 94,
    UsnJournalOp = 95,
    ChangeJournalOp = 96,
    IndexOp = 97,
    AttributeOp = 98,
    PropertyOp = 99,
    SecurityDescriptorOp = 100,
    AclOp = 101,
    AceOp = 102,
    SidOp = 103,
    TrustOp = 104,
    PolicyOp = 105,
    LsaOp = 106,
    SamOp = 107,
    AdsOp = 108,
    DsOp = 109,
    LdapOp = 110,
    KerberosOp = 111,
    NtlmOp = 112,
    SspiOp = 113,
    SchannelOp = 114,
    CryptoApiOp = 115,
    CngOp = 116,
    BcryptOp = 117,
    NcryptOp = 118,
    TpmOp = 119,
    SmartCardOp = 120,
    BiometricOp = 121,
    CredentialOp = 122,
    VaultOp = 123,
    ProtectorOp = 124,
    RecoveryOp = 125,
    BackupKeyOp = 126,
    EfsOp = 127,
    BitlockerOp = 128,
    TpmVirtualizationOp = 129,
    MeasuredBootOp = 130,
    SecureBootOp = 131,
    CodeIntegrityOp = 132,
    DeviceGuardOp = 133,
    CredentialGuardOp = 134,
    AppLockerOp = 135,
    WdacOp = 136,
    ExploitProtectionOp = 137,
    AttackSurfaceReductionOp = 138,
    ControlledFolderAccessOp = 139,
    NetworkProtectionOp = 140,
    WebProtectionOp = 141,
    PhishingProtectionOp = 142,
    ApplicationControlOp = 143,
    DeviceControlOp = 144,
    EndpointProtectionOp = 145,
    ThreatProtectionOp = 146,
    VulnerabilityProtectionOp = 147,
    MalwareProtectionOp = 148,
    RansomwareProtectionOp = 149,
    DataProtectionOp = 150,
    PrivacyProtectionOp = 151,
    ComplianceOp = 152,
    GovernanceOp = 153,
    RiskOp = 154,
    IncidentOp = 155,
    InvestigationOp = 156,
    ResponseOp = 157,
    HuntingOp = 158,
    DetectionOp = 159,
    PreventionOp = 160,
    RemediationOp = 161,
    IsolationOp = 162,
    EradicationOp = 163,
    RecoveryOp2 = 164,
    LessonsLearnedOp = 165,
    ImprovementOp = 166,
    MetricsOp = 167,
    ReportingOp = 168,
    DashboardOp = 169,
    AlertOp = 170,
    NotificationOp = 171,
    EscalationOp = 172,
    WorkflowOp = 173,
    AutomationOp = 174,
    OrchestrationOp = 175,
    IntegrationOp = 176,
    ApiOp = 177,
    WebhookOp = 178,
    EventOp2 = 179,
    LogOp = 180,
    TelemetryOp = 181,
    DiagnosticsOp = 182,
    HealthOp = 183,
    MonitoringOp = 184,
    ObservabilityOp = 185,
    TracingOp = 186,
    ProfilingOp = 187,
    DebuggingOp = 188,
    TestingOp = 189,
    ValidationOp = 190,
    VerificationOp = 191,
    CertificationOp = 192,
    AttestationOp = 193,
    ProvisioningOp = 194,
    DeploymentOp = 195,
    ConfigurationOp = 196,
    ManagementOp = 197,
    MaintenanceOp = 198,
    SupportOp = 199,
    DocumentationOp = 200,
}

impl ApiType {
    /// 从 u32 创建 ApiType
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::MemoryRead,
            2 => Self::MemoryWrite,
            3 => Self::MemoryAlloc,
            4 => Self::MemoryFree,
            5 => Self::StringOp,
            6 => Self::CryptoOp,
            7 => Self::FileOp,
            8 => Self::RegistryOp,
            9 => Self::NetworkOp,
            10 => Self::ProcessOp,
            11 => Self::ThreadOp,
            12 => Self::Synchronization,
            13 => Self::DebugOp,
            14 => Self::Virtualization,
            15 => Self::AntiDebug,
            16 => Self::Compression,
            17 => Self::Hashing,
            18 => Self::Encryption,
            19 => Self::Decryption,
            20 => Self::Random,
            21 => Self::Time,
            22 => Self::Environment,
            23 => Self::SystemInfo,
            24 => Self::ModuleOp,
            25 => Self::ExceptionOp,
            26 => Self::MemoryProtect,
            27 => Self::Ipc,
            28 => Self::ServiceOp,
            29 => Self::UserOp,
            30 => Self::SecurityOp,
            31 => Self::TokenOp,
            32 => Self::PrivilegeOp,
            33 => Self::AuditOp,
            34 => Self::EventLog,
            35 => Self::Performance,
            36 => Self::PowerOp,
            37 => Self::DeviceOp,
            38 => Self::DriverOp,
            39 => Self::IoOp,
            40 => Self::DmaOp,
            41 => Self::InterruptOp,
            42 => Self::ApicOp,
            43 => Self::MmOp,
            44 => Self::PnPOp,
            45 => Self::WmiOp,
            46 => Self::SetupOp,
            47 => Self::ConfigOp,
            48 => Self::UpdateOp,
            49 => Self::BackupOp,
            50 => Self::RestoreOp,
            51 => Self::MigrationOp,
            52 => Self::ReplicationOp,
            53 => Self::ClusterOp,
            54 => Self::StorageOp,
            55 => Self::FsOp,
            56 => Self::VolumeOp,
            57 => Self::DiskOp,
            58 => Self::PartitionOp,
            59 => Self::MountOp,
            60 => Self::ShareOp,
            61 => Self::PrintOp,
            62 => Self::JobOp,
            63 => Self::TaskOp,
            64 => Self::ScheduleOp,
            65 => Self::TimerOp,
            66 => Self::WaitOp,
            67 => Self::SignalOp,
            68 => Self::EventOp,
            69 => Self::MutexOp,
            70 => Self::SemaphoreOp,
            71 => Self::CriticalSectionOp,
            72 => Self::RwLockOp,
            73 => Self::BarrierOp,
            74 => Self::ConditionOp,
            75 => Self::MonitorOp,
            76 => Self::SpinLockOp,
            77 => Self::AtomicOp,
            78 => Self::TransactionOp,
            79 => Self::ResourceOp,
            80 => Self::HandleOp,
            81 => Self::ObjectOp,
            82 => Self::DirectoryOp,
            83 => Self::SymbolicLinkOp,
            84 => Self::JunctionOp,
            85 => Self::ReparseOp,
            86 => Self::StreamOp,
            87 => Self::AlternateDataStreamOp,
            88 => Self::ExtendedAttributeOp,
            89 => Self::SparseFileOp,
            90 => Self::CompressionOp,
            91 => Self::EncryptionOp,
            92 => Self::QuotaOp,
            93 => Self::ObjectIdOp,
            94 => Self::ReparsePointOp,
            95 => Self::UsnJournalOp,
            96 => Self::ChangeJournalOp,
            97 => Self::IndexOp,
            98 => Self::AttributeOp,
            99 => Self::PropertyOp,
            100 => Self::SecurityDescriptorOp,
            101 => Self::AclOp,
            102 => Self::AceOp,
            103 => Self::SidOp,
            104 => Self::TrustOp,
            105 => Self::PolicyOp,
            106 => Self::LsaOp,
            107 => Self::SamOp,
            108 => Self::AdsOp,
            109 => Self::DsOp,
            110 => Self::LdapOp,
            111 => Self::KerberosOp,
            112 => Self::NtlmOp,
            113 => Self::SspiOp,
            114 => Self::SchannelOp,
            115 => Self::CryptoApiOp,
            116 => Self::CngOp,
            117 => Self::BcryptOp,
            118 => Self::NcryptOp,
            119 => Self::TpmOp,
            120 => Self::SmartCardOp,
            121 => Self::BiometricOp,
            122 => Self::CredentialOp,
            123 => Self::VaultOp,
            124 => Self::ProtectorOp,
            125 => Self::RecoveryOp,
            126 => Self::BackupKeyOp,
            127 => Self::EfsOp,
            128 => Self::BitlockerOp,
            129 => Self::TpmVirtualizationOp,
            130 => Self::MeasuredBootOp,
            131 => Self::SecureBootOp,
            132 => Self::CodeIntegrityOp,
            133 => Self::DeviceGuardOp,
            134 => Self::CredentialGuardOp,
            135 => Self::AppLockerOp,
            136 => Self::WdacOp,
            137 => Self::ExploitProtectionOp,
            138 => Self::AttackSurfaceReductionOp,
            139 => Self::ControlledFolderAccessOp,
            140 => Self::NetworkProtectionOp,
            141 => Self::WebProtectionOp,
            142 => Self::PhishingProtectionOp,
            143 => Self::ApplicationControlOp,
            144 => Self::DeviceControlOp,
            145 => Self::EndpointProtectionOp,
            146 => Self::ThreatProtectionOp,
            147 => Self::VulnerabilityProtectionOp,
            148 => Self::MalwareProtectionOp,
            149 => Self::RansomwareProtectionOp,
            150 => Self::DataProtectionOp,
            151 => Self::PrivacyProtectionOp,
            152 => Self::ComplianceOp,
            153 => Self::GovernanceOp,
            154 => Self::RiskOp,
            155 => Self::IncidentOp,
            156 => Self::InvestigationOp,
            157 => Self::ResponseOp,
            158 => Self::HuntingOp,
            159 => Self::DetectionOp,
            160 => Self::PreventionOp,
            161 => Self::RemediationOp,
            162 => Self::IsolationOp,
            163 => Self::EradicationOp,
            164 => Self::RecoveryOp2,
            165 => Self::LessonsLearnedOp,
            166 => Self::ImprovementOp,
            167 => Self::MetricsOp,
            168 => Self::ReportingOp,
            169 => Self::DashboardOp,
            170 => Self::AlertOp,
            171 => Self::NotificationOp,
            172 => Self::EscalationOp,
            173 => Self::WorkflowOp,
            174 => Self::AutomationOp,
            175 => Self::OrchestrationOp,
            176 => Self::IntegrationOp,
            177 => Self::ApiOp,
            178 => Self::WebhookOp,
            179 => Self::EventOp2,
            180 => Self::LogOp,
            181 => Self::TelemetryOp,
            182 => Self::DiagnosticsOp,
            183 => Self::HealthOp,
            184 => Self::MonitoringOp,
            185 => Self::ObservabilityOp,
            186 => Self::TracingOp,
            187 => Self::ProfilingOp,
            188 => Self::DebuggingOp,
            189 => Self::TestingOp,
            190 => Self::ValidationOp,
            191 => Self::VerificationOp,
            192 => Self::CertificationOp,
            193 => Self::AttestationOp,
            194 => Self::ProvisioningOp,
            195 => Self::DeploymentOp,
            196 => Self::ConfigurationOp,
            197 => Self::ManagementOp,
            198 => Self::MaintenanceOp,
            199 => Self::SupportOp,
            200 => Self::DocumentationOp,
            _ => Self::None,
        }
    }

    /// 获取 API 类型的描述
    pub fn description(&self) -> &'static str {
        match self {
            Self::None => "No specific API type",
            Self::MemoryRead => "Memory read operation",
            Self::MemoryWrite => "Memory write operation",
            Self::MemoryAlloc => "Memory allocation",
            Self::MemoryFree => "Memory deallocation",
            Self::StringOp => "String operation",
            Self::CryptoOp => "Cryptographic operation",
            Self::FileOp => "File operation",
            Self::RegistryOp => "Registry operation",
            Self::NetworkOp => "Network operation",
            Self::ProcessOp => "Process operation",
            Self::ThreadOp => "Thread operation",
            Self::Synchronization => "Synchronization primitive",
            Self::DebugOp => "Debug operation",
            Self::Virtualization => "Virtualization operation",
            Self::AntiDebug => "Anti-debugging operation",
            Self::Compression => "Compression operation",
            Self::Hashing => "Hashing operation",
            Self::Encryption => "Encryption operation",
            Self::Decryption => "Decryption operation",
            Self::Random => "Random number generation",
            Self::Time => "Time operation",
            Self::Environment => "Environment operation",
            Self::SystemInfo => "System information",
            Self::ModuleOp => "Module operation",
            Self::ExceptionOp => "Exception handling",
            Self::MemoryProtect => "Memory protection",
            Self::Ipc => "Inter-process communication",
            Self::ServiceOp => "Service operation",
            Self::UserOp => "User operation",
            Self::SecurityOp => "Security operation",
            Self::TokenOp => "Token operation",
            Self::PrivilegeOp => "Privilege operation",
            Self::AuditOp => "Audit operation",
            Self::EventLog => "Event log operation",
            Self::Performance => "Performance operation",
            Self::PowerOp => "Power operation",
            Self::DeviceOp => "Device operation",
            Self::DriverOp => "Driver operation",
            Self::IoOp => "I/O operation",
            Self::DmaOp => "DMA operation",
            Self::InterruptOp => "Interrupt operation",
            Self::ApicOp => "APIC operation",
            Self::MmOp => "Memory manager operation",
            Self::PnPOp => "Plug and Play operation",
            Self::WmiOp => "WMI operation",
            Self::SetupOp => "Setup operation",
            Self::ConfigOp => "Configuration operation",
            Self::UpdateOp => "Update operation",
            Self::BackupOp => "Backup operation",
            Self::RestoreOp => "Restore operation",
            Self::MigrationOp => "Migration operation",
            Self::ReplicationOp => "Replication operation",
            Self::ClusterOp => "Cluster operation",
            Self::StorageOp => "Storage operation",
            Self::FsOp => "File system operation",
            Self::VolumeOp => "Volume operation",
            Self::DiskOp => "Disk operation",
            Self::PartitionOp => "Partition operation",
            Self::MountOp => "Mount operation",
            Self::ShareOp => "Share operation",
            Self::PrintOp => "Print operation",
            Self::JobOp => "Job operation",
            Self::TaskOp => "Task operation",
            Self::ScheduleOp => "Schedule operation",
            Self::TimerOp => "Timer operation",
            Self::WaitOp => "Wait operation",
            Self::SignalOp => "Signal operation",
            Self::EventOp => "Event operation",
            Self::MutexOp => "Mutex operation",
            Self::SemaphoreOp => "Semaphore operation",
            Self::CriticalSectionOp => "Critical section operation",
            Self::RwLockOp => "Read-write lock operation",
            Self::BarrierOp => "Barrier operation",
            Self::ConditionOp => "Condition variable operation",
            Self::MonitorOp => "Monitor operation",
            Self::SpinLockOp => "Spin lock operation",
            Self::AtomicOp => "Atomic operation",
            Self::TransactionOp => "Transaction operation",
            Self::ResourceOp => "Resource operation",
            Self::HandleOp => "Handle operation",
            Self::ObjectOp => "Object operation",
            Self::DirectoryOp => "Directory operation",
            Self::SymbolicLinkOp => "Symbolic link operation",
            Self::JunctionOp => "Junction operation",
            Self::ReparseOp => "Reparse point operation",
            Self::StreamOp => "Stream operation",
            Self::AlternateDataStreamOp => "Alternate data stream operation",
            Self::ExtendedAttributeOp => "Extended attribute operation",
            Self::SparseFileOp => "Sparse file operation",
            Self::CompressionOp => "Compression operation",
            Self::EncryptionOp => "Encryption operation",
            Self::QuotaOp => "Quota operation",
            Self::ObjectIdOp => "Object ID operation",
            Self::ReparsePointOp => "Reparse point operation",
            Self::UsnJournalOp => "USN journal operation",
            Self::ChangeJournalOp => "Change journal operation",
            Self::IndexOp => "Index operation",
            Self::AttributeOp => "Attribute operation",
            Self::PropertyOp => "Property operation",
            Self::SecurityDescriptorOp => "Security descriptor operation",
            Self::AclOp => "ACL operation",
            Self::AceOp => "ACE operation",
            Self::SidOp => "SID operation",
            Self::TrustOp => "Trust operation",
            Self::PolicyOp => "Policy operation",
            Self::LsaOp => "LSA operation",
            Self::SamOp => "SAM operation",
            Self::AdsOp => "ADs operation",
            Self::DsOp => "Directory service operation",
            Self::LdapOp => "LDAP operation",
            Self::KerberosOp => "Kerberos operation",
            Self::NtlmOp => "NTLM operation",
            Self::SspiOp => "SSPI operation",
            Self::SchannelOp => "Schannel operation",
            Self::CryptoApiOp => "Crypto API operation",
            Self::CngOp => "CNG operation",
            Self::BcryptOp => "BCrypt operation",
            Self::NcryptOp => "NCrypt operation",
            Self::TpmOp => "TPM operation",
            Self::SmartCardOp => "Smart card operation",
            Self::BiometricOp => "Biometric operation",
            Self::CredentialOp => "Credential operation",
            Self::VaultOp => "Vault operation",
            Self::ProtectorOp => "Protector operation",
            Self::RecoveryOp => "Recovery operation",
            Self::BackupKeyOp => "Backup key operation",
            Self::EfsOp => "EFS operation",
            Self::BitlockerOp => "BitLocker operation",
            Self::TpmVirtualizationOp => "TPM virtualization operation",
            Self::MeasuredBootOp => "Measured boot operation",
            Self::SecureBootOp => "Secure boot operation",
            Self::CodeIntegrityOp => "Code integrity operation",
            Self::DeviceGuardOp => "Device Guard operation",
            Self::CredentialGuardOp => "Credential Guard operation",
            Self::AppLockerOp => "AppLocker operation",
            Self::WdacOp => "WDAC operation",
            Self::ExploitProtectionOp => "Exploit protection operation",
            Self::AttackSurfaceReductionOp => "Attack surface reduction operation",
            Self::ControlledFolderAccessOp => "Controlled folder access operation",
            Self::NetworkProtectionOp => "Network protection operation",
            Self::WebProtectionOp => "Web protection operation",
            Self::PhishingProtectionOp => "Phishing protection operation",
            Self::ApplicationControlOp => "Application control operation",
            Self::DeviceControlOp => "Device control operation",
            Self::EndpointProtectionOp => "Endpoint protection operation",
            Self::ThreatProtectionOp => "Threat protection operation",
            Self::VulnerabilityProtectionOp => "Vulnerability protection operation",
            Self::MalwareProtectionOp => "Malware protection operation",
            Self::RansomwareProtectionOp => "Ransomware protection operation",
            Self::DataProtectionOp => "Data protection operation",
            Self::PrivacyProtectionOp => "Privacy protection operation",
            Self::ComplianceOp => "Compliance operation",
            Self::GovernanceOp => "Governance operation",
            Self::RiskOp => "Risk operation",
            Self::IncidentOp => "Incident operation",
            Self::InvestigationOp => "Investigation operation",
            Self::ResponseOp => "Response operation",
            Self::HuntingOp => "Hunting operation",
            Self::DetectionOp => "Detection operation",
            Self::PreventionOp => "Prevention operation",
            Self::RemediationOp => "Remediation operation",
            Self::IsolationOp => "Isolation operation",
            Self::EradicationOp => "Eradication operation",
            Self::RecoveryOp2 => "Recovery operation",
            Self::LessonsLearnedOp => "Lessons learned operation",
            Self::ImprovementOp => "Improvement operation",
            Self::MetricsOp => "Metrics operation",
            Self::ReportingOp => "Reporting operation",
            Self::DashboardOp => "Dashboard operation",
            Self::AlertOp => "Alert operation",
            Self::NotificationOp => "Notification operation",
            Self::EscalationOp => "Escalation operation",
            Self::WorkflowOp => "Workflow operation",
            Self::AutomationOp => "Automation operation",
            Self::OrchestrationOp => "Orchestration operation",
            Self::IntegrationOp => "Integration operation",
            Self::ApiOp => "API operation",
            Self::WebhookOp => "Webhook operation",
            Self::EventOp2 => "Event operation",
            Self::LogOp => "Log operation",
            Self::TelemetryOp => "Telemetry operation",
            Self::DiagnosticsOp => "Diagnostics operation",
            Self::HealthOp => "Health operation",
            Self::MonitoringOp => "Monitoring operation",
            Self::ObservabilityOp => "Observability operation",
            Self::TracingOp => "Tracing operation",
            Self::ProfilingOp => "Profiling operation",
            Self::DebuggingOp => "Debugging operation",
            Self::TestingOp => "Testing operation",
            Self::ValidationOp => "Validation operation",
            Self::VerificationOp => "Verification operation",
            Self::CertificationOp => "Certification operation",
            Self::AttestationOp => "Attestation operation",
            Self::ProvisioningOp => "Provisioning operation",
            Self::DeploymentOp => "Deployment operation",
            Self::ConfigurationOp => "Configuration operation",
            Self::ManagementOp => "Management operation",
            Self::MaintenanceOp => "Maintenance operation",
            Self::SupportOp => "Support operation",
            Self::DocumentationOp => "Documentation operation",
        }
    }

    /// 检查是否是安全相关的 API
    pub fn is_security_related(&self) -> bool {
        matches!(self,
            Self::CryptoOp | Self::Encryption | Self::Decryption | Self::Hashing |
            Self::SecurityOp | Self::TokenOp | Self::PrivilegeOp | Self::AuditOp |
            Self::KerberosOp | Self::NtlmOp | Self::SspiOp | Self::SchannelOp |
            Self::CryptoApiOp | Self::CngOp | Self::BcryptOp | Self::NcryptOp |
            Self::TpmOp | Self::SmartCardOp | Self::BiometricOp | Self::CredentialOp |
            Self::VaultOp | Self::ProtectorOp | Self::EfsOp | Self::BitlockerOp |
            Self::CodeIntegrityOp | Self::DeviceGuardOp | Self::CredentialGuardOp |
            Self::AppLockerOp | Self::WdacOp | Self::ExploitProtectionOp |
            Self::AttackSurfaceReductionOp | Self::ControlledFolderAccessOp |
            Self::NetworkProtectionOp | Self::WebProtectionOp | Self::PhishingProtectionOp |
            Self::ApplicationControlOp | Self::DeviceControlOp | Self::EndpointProtectionOp |
            Self::ThreatProtectionOp | Self::VulnerabilityProtectionOp |
            Self::MalwareProtectionOp | Self::RansomwareProtectionOp |
            Self::DataProtectionOp | Self::PrivacyProtectionOp
        )
    }

    /// 检查是否是调试相关的 API
    pub fn is_debug_related(&self) -> bool {
        matches!(self,
            Self::DebugOp | Self::AntiDebug | Self::DebuggingOp | Self::TracingOp |
            Self::ProfilingOp | Self::DiagnosticsOp | Self::TelemetryOp
        )
    }

    /// 检查是否是内存相关的 API
    pub fn is_memory_related(&self) -> bool {
        matches!(self,
            Self::MemoryRead | Self::MemoryWrite | Self::MemoryAlloc | Self::MemoryFree |
            Self::MemoryProtect | Self::MmOp
        )
    }
}

/// 编译类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CompilationType {
    Default = 0,
    Virtualized = 1,
    Mutated = 2,
    Ultra = 3,
    NoCompilation = 4,
}

impl CompilationType {
    /// 从 u32 创建编译类型
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Default,
            1 => Self::Virtualized,
            2 => Self::Mutated,
            3 => Self::Ultra,
            4 => Self::NoCompilation,
            _ => Self::Default,
        }
    }

    /// 获取编译类型的描述
    pub fn description(&self) -> &'static str {
        match self {
            Self::Default => "Default compilation",
            Self::Virtualized => "Virtualized code",
            Self::Mutated => "Mutated code",
            Self::Ultra => "Ultra protection",
            Self::NoCompilation => "No compilation/protection",
        }
    }

    /// 检查是否需要虚拟化
    pub fn needs_virtualization(&self) -> bool {
        matches!(self, Self::Virtualized | Self::Ultra)
    }

    /// 检查是否需要变异
    pub fn needs_mutation(&self) -> bool {
        matches!(self, Self::Mutated | Self::Ultra)
    }
}

/// 导入选项标志
pub struct ImportOption;
#[allow(dead_code)]
impl ImportOption {
    pub const PROTECTED: u32 = 1 << 0;      // 受保护导入
    pub const HIDDEN: u32 = 1 << 1;         // 隐藏导入
    pub const ENCRYPTED: u32 = 1 << 2;      // 加密导入
    pub const DELAYED: u32 = 1 << 3;        // 延迟导入
    pub const DYNAMIC: u32 = 1 << 4;        // 动态导入
    pub const FORWARDED: u32 = 1 << 5;      // 转发导入
    pub const BOUND: u32 = 1 << 6;          // 绑定导入
    pub const SNAP_BY_ORDINAL: u32 = 1 << 7; // 按序号导入
}

/// 函数映射信息
#[derive(Debug, Clone)]
pub struct MapFunction {
    pub name: String,
    pub dll_name: String,
    pub api_type: ApiType,
    pub options: u32,           // 导入选项
    pub compilation_type: CompilationType,
    pub address: u64,
    pub is_sdk: bool,           // 是否是 SDK 函数
    pub runtime_options: u32,   // 运行时选项
    pub sdk_options: u32,       // SDK 选项
}

impl MapFunction {
    /// 创建新的 MapFunction
    pub fn new(name: String, dll_name: String) -> Self {
        Self {
            name,
            dll_name,
            api_type: ApiType::None,
            options: 0,
            compilation_type: CompilationType::Default,
            address: 0,
            is_sdk: false,
            runtime_options: 0,
            sdk_options: 0,
        }
    }

    /// 从名称创建映射函数
    pub fn from_name(dll_name: &str, func_name: &str) -> Option<Self> {
        let api_type = MapFunctionDatabase::lookup_api_type(dll_name, func_name);
        
        Some(Self {
            name: func_name.to_string(),
            dll_name: dll_name.to_string(),
            api_type,
            options: 0,
            compilation_type: CompilationType::Default,
            address: 0,
            is_sdk: false,
            runtime_options: 0,
            sdk_options: 0,
        })
    }

    /// 从序号创建映射函数
    pub fn from_ordinal(dll_name: &str, ordinal: u16) -> Option<Self> {
        Some(Self {
            name: format!("Ordinal_{}", ordinal),
            dll_name: dll_name.to_string(),
            api_type: ApiType::None,
            options: ImportOption::SNAP_BY_ORDINAL,
            compilation_type: CompilationType::Default,
            address: 0,
            is_sdk: false,
            runtime_options: 0,
            sdk_options: 0,
        })
    }

    /// 获取完整名称（DLL!Function）
    pub fn full_name(&self) -> String {
        format!("{}!{}", self.dll_name, self.name)
    }

    /// 检查是否是内部函数
    pub fn is_internal(&self) -> bool {
        self.dll_name.is_empty() || self.dll_name == "self"
    }

    /// 获取运行时选项
    pub fn get_runtime_options(&self) -> u32 {
        self.runtime_options
    }

    /// 获取 SDK 选项
    pub fn get_sdk_options(&self) -> u32 {
        self.sdk_options
    }

    /// 设置 API 类型
    pub fn with_api_type(mut self, api_type: ApiType) -> Self {
        self.api_type = api_type;
        self
    }

    /// 设置编译类型
    pub fn with_compilation_type(mut self, compilation_type: CompilationType) -> Self {
        self.compilation_type = compilation_type;
        self
    }

    /// 设置地址
    pub fn with_address(mut self, address: u64) -> Self {
        self.address = address;
        self
    }

    /// 设置是否为 SDK 函数
    pub fn with_sdk(mut self, is_sdk: bool) -> Self {
        self.is_sdk = is_sdk;
        self
    }

    /// 包含导入选项
    pub fn include_option(&mut self, option: u32) {
        self.options |= option;
    }

    /// 排除导入选项
    pub fn exclude_option(&mut self, option: u32) {
        self.options &= !option;
    }

    /// 检查是否包含选项
    pub fn has_option(&self, option: u32) -> bool {
        (self.options & option) != 0
    }

    /// 设置运行时选项
    pub fn set_runtime_options(&mut self, options: u32) {
        self.runtime_options = options;
    }

    /// 设置 SDK 选项
    pub fn set_sdk_options(&mut self, options: u32) {
        self.sdk_options = options;
    }
}

/// 预定义的 API 映射数据库
pub struct MapFunctionDatabase;

impl MapFunctionDatabase {
    /// 获取 kernel32.dll 的 API 映射
    pub fn get_kernel32_apis() -> &'static [(&'static str, ApiType)] {
        &[
            ("ReadProcessMemory", ApiType::MemoryRead),
            ("WriteProcessMemory", ApiType::MemoryWrite),
            ("VirtualAlloc", ApiType::MemoryAlloc),
            ("VirtualAllocEx", ApiType::MemoryAlloc),
            ("VirtualFree", ApiType::MemoryFree),
            ("VirtualFreeEx", ApiType::MemoryFree),
            ("VirtualProtect", ApiType::MemoryProtect),
            ("VirtualProtectEx", ApiType::MemoryProtect),
            ("CreateFileA", ApiType::FileOp),
            ("CreateFileW", ApiType::FileOp),
            ("ReadFile", ApiType::FileOp),
            ("WriteFile", ApiType::FileOp),
            ("CloseHandle", ApiType::HandleOp),
            ("CreateProcessA", ApiType::ProcessOp),
            ("CreateProcessW", ApiType::ProcessOp),
            ("CreateThread", ApiType::ThreadOp),
            ("WaitForSingleObject", ApiType::WaitOp),
            ("WaitForMultipleObjects", ApiType::WaitOp),
            ("Sleep", ApiType::WaitOp),
            ("GetTickCount", ApiType::Time),
            ("QueryPerformanceCounter", ApiType::Performance),
            ("GetSystemTime", ApiType::Time),
            ("GetLocalTime", ApiType::Time),
            ("GetSystemInfo", ApiType::SystemInfo),
            ("GetComputerNameA", ApiType::SystemInfo),
            ("GetComputerNameW", ApiType::SystemInfo),
            ("GetUserNameA", ApiType::UserOp),
            ("GetUserNameW", ApiType::UserOp),
            ("LoadLibraryA", ApiType::ModuleOp),
            ("LoadLibraryW", ApiType::ModuleOp),
            ("LoadLibraryExA", ApiType::ModuleOp),
            ("LoadLibraryExW", ApiType::ModuleOp),
            ("GetProcAddress", ApiType::ModuleOp),
            ("FreeLibrary", ApiType::ModuleOp),
            ("IsDebuggerPresent", ApiType::AntiDebug),
            ("CheckRemoteDebuggerPresent", ApiType::AntiDebug),
            ("OutputDebugStringA", ApiType::DebugOp),
            ("OutputDebugStringW", ApiType::DebugOp),
            ("DebugActiveProcess", ApiType::DebugOp),
            ("ContinueDebugEvent", ApiType::DebugOp),
            ("WaitForDebugEvent", ApiType::DebugOp),
            ("CreateMutexA", ApiType::MutexOp),
            ("CreateMutexW", ApiType::MutexOp),
            ("CreateSemaphoreA", ApiType::SemaphoreOp),
            ("CreateSemaphoreW", ApiType::SemaphoreOp),
            ("CreateEventA", ApiType::EventOp),
            ("CreateEventW", ApiType::EventOp),
            ("InitializeCriticalSection", ApiType::CriticalSectionOp),
            ("EnterCriticalSection", ApiType::CriticalSectionOp),
            ("LeaveCriticalSection", ApiType::CriticalSectionOp),
            ("DeleteCriticalSection", ApiType::CriticalSectionOp),
            ("GetEnvironmentVariableA", ApiType::Environment),
            ("GetEnvironmentVariableW", ApiType::Environment),
            ("SetEnvironmentVariableA", ApiType::Environment),
            ("SetEnvironmentVariableW", ApiType::Environment),
            ("ExpandEnvironmentStringsA", ApiType::Environment),
            ("ExpandEnvironmentStringsW", ApiType::Environment),
            ("GetCurrentProcess", ApiType::ProcessOp),
            ("GetCurrentProcessId", ApiType::ProcessOp),
            ("GetCurrentThread", ApiType::ThreadOp),
            ("GetCurrentThreadId", ApiType::ThreadOp),
            ("OpenProcess", ApiType::ProcessOp),
            ("OpenThread", ApiType::ThreadOp),
            ("TerminateProcess", ApiType::ProcessOp),
            ("TerminateThread", ApiType::ThreadOp),
            ("SuspendThread", ApiType::ThreadOp),
            ("ResumeThread", ApiType::ThreadOp),
            ("GetThreadContext", ApiType::ThreadOp),
            ("SetThreadContext", ApiType::ThreadOp),
            ("FlushInstructionCache", ApiType::MemoryProtect),
            ("lstrlenA", ApiType::StringOp),
            ("lstrlenW", ApiType::StringOp),
            ("lstrcmpA", ApiType::StringOp),
            ("lstrcmpW", ApiType::StringOp),
            ("lstrcmpiA", ApiType::StringOp),
            ("lstrcmpiW", ApiType::StringOp),
            ("lstrcpyA", ApiType::StringOp),
            ("lstrcpyW", ApiType::StringOp),
            ("lstrcatA", ApiType::StringOp),
            ("lstrcatW", ApiType::StringOp),
        ]
    }

    /// 获取 ntdll.dll 的 API 映射
    pub fn get_ntdll_apis() -> &'static [(&'static str, ApiType)] {
        &[
            ("NtReadVirtualMemory", ApiType::MemoryRead),
            ("NtWriteVirtualMemory", ApiType::MemoryWrite),
            ("NtAllocateVirtualMemory", ApiType::MemoryAlloc),
            ("NtFreeVirtualMemory", ApiType::MemoryFree),
            ("NtProtectVirtualMemory", ApiType::MemoryProtect),
            ("NtQueryVirtualMemory", ApiType::MemoryRead),
            ("NtCreateFile", ApiType::FileOp),
            ("NtReadFile", ApiType::FileOp),
            ("NtWriteFile", ApiType::FileOp),
            ("NtClose", ApiType::HandleOp),
            ("NtCreateProcess", ApiType::ProcessOp),
            ("NtCreateProcessEx", ApiType::ProcessOp),
            ("NtCreateThread", ApiType::ThreadOp),
            ("NtCreateThreadEx", ApiType::ThreadOp),
            ("NtWaitForSingleObject", ApiType::WaitOp),
            ("NtWaitForMultipleObjects", ApiType::WaitOp),
            ("NtDelayExecution", ApiType::WaitOp),
            ("NtQuerySystemInformation", ApiType::SystemInfo),
            ("NtQueryInformationProcess", ApiType::ProcessOp),
            ("NtQueryInformationThread", ApiType::ThreadOp),
            ("NtSetInformationProcess", ApiType::ProcessOp),
            ("NtSetInformationThread", ApiType::ThreadOp),
            ("NtOpenProcess", ApiType::ProcessOp),
            ("NtOpenThread", ApiType::ThreadOp),
            ("NtTerminateProcess", ApiType::ProcessOp),
            ("NtTerminateThread", ApiType::ThreadOp),
            ("NtSuspendThread", ApiType::ThreadOp),
            ("NtResumeThread", ApiType::ThreadOp),
            ("NtGetContextThread", ApiType::ThreadOp),
            ("NtSetContextThread", ApiType::ThreadOp),
            ("NtUnmapViewOfSection", ApiType::MemoryFree),
            ("NtMapViewOfSection", ApiType::MemoryAlloc),
            ("NtCreateSection", ApiType::MemoryAlloc),
            ("NtOpenSection", ApiType::MemoryAlloc),
            ("NtQuerySection", ApiType::MemoryRead),
            ("RtlInitUnicodeString", ApiType::StringOp),
            ("RtlInitAnsiString", ApiType::StringOp),
            ("RtlCompareUnicodeString", ApiType::StringOp),
            ("RtlCompareString", ApiType::StringOp),
            ("RtlCopyUnicodeString", ApiType::StringOp),
            ("RtlCopyString", ApiType::StringOp),
            ("RtlAppendUnicodeStringToString", ApiType::StringOp),
            ("RtlAppendStringToString", ApiType::StringOp),
            ("RtlHashUnicodeString", ApiType::Hashing),
            ("RtlRandom", ApiType::Random),
            ("RtlRandomEx", ApiType::Random),
            ("RtlGetVersion", ApiType::SystemInfo),
            ("NtQueryPerformanceCounter", ApiType::Performance),
            ("NtQuerySystemTime", ApiType::Time),
            ("DbgPrint", ApiType::DebugOp),
            ("DbgPrintEx", ApiType::DebugOp),
            ("NtDebugActiveProcess", ApiType::DebugOp),
            ("NtRemoveProcessDebug", ApiType::DebugOp),
            ("NtWaitForDebugEvent", ApiType::DebugOp),
            ("NtContinue", ApiType::ExceptionOp),
            ("NtRaiseException", ApiType::ExceptionOp),
            ("NtRaiseHardError", ApiType::ExceptionOp),
            ("RtlDispatchException", ApiType::ExceptionOp),
            ("RtlUnhandledExceptionFilter", ApiType::ExceptionOp),
        ]
    }

    /// 获取 user32.dll 的 API 映射
    pub fn get_user32_apis() -> &'static [(&'static str, ApiType)] {
        &[
            ("SendMessageA", ApiType::Ipc),
            ("SendMessageW", ApiType::Ipc),
            ("PostMessageA", ApiType::Ipc),
            ("PostMessageW", ApiType::Ipc),
            ("FindWindowA", ApiType::Ipc),
            ("FindWindowW", ApiType::Ipc),
            ("FindWindowExA", ApiType::Ipc),
            ("FindWindowExW", ApiType::Ipc),
            ("EnumWindows", ApiType::Ipc),
            ("GetWindowTextA", ApiType::Ipc),
            ("GetWindowTextW", ApiType::Ipc),
            ("SetWindowTextA", ApiType::Ipc),
            ("SetWindowTextW", ApiType::Ipc),
            ("RegisterClassA", ApiType::Ipc),
            ("RegisterClassW", ApiType::Ipc),
            ("RegisterClassExA", ApiType::Ipc),
            ("RegisterClassExW", ApiType::Ipc),
            ("CreateWindowExA", ApiType::Ipc),
            ("CreateWindowExW", ApiType::Ipc),
            ("DestroyWindow", ApiType::Ipc),
            ("ShowWindow", ApiType::Ipc),
            ("UpdateWindow", ApiType::Ipc),
            ("GetMessageA", ApiType::Ipc),
            ("GetMessageW", ApiType::Ipc),
            ("PeekMessageA", ApiType::Ipc),
            ("PeekMessageW", ApiType::Ipc),
            ("TranslateMessage", ApiType::Ipc),
            ("DispatchMessageA", ApiType::Ipc),
            ("DispatchMessageW", ApiType::Ipc),
            ("MessageBoxA", ApiType::Ipc),
            ("MessageBoxW", ApiType::Ipc),
            ("SetTimer", ApiType::TimerOp),
            ("KillTimer", ApiType::TimerOp),
            ("SetWindowsHookExA", ApiType::Ipc),
            ("SetWindowsHookExW", ApiType::Ipc),
            ("UnhookWindowsHookEx", ApiType::Ipc),
            ("CallNextHookEx", ApiType::Ipc),
            ("GetAsyncKeyState", ApiType::Ipc),
            ("GetKeyState", ApiType::Ipc),
            ("GetKeyboardState", ApiType::Ipc),
            ("SetKeyboardState", ApiType::Ipc),
            ("GetCursorPos", ApiType::Ipc),
            ("SetCursorPos", ApiType::Ipc),
            ("GetDC", ApiType::DeviceOp),
            ("ReleaseDC", ApiType::DeviceOp),
            ("GetWindowDC", ApiType::DeviceOp),
            ("BeginPaint", ApiType::DeviceOp),
            ("EndPaint", ApiType::DeviceOp),
            ("InvalidateRect", ApiType::DeviceOp),
            ("ValidateRect", ApiType::DeviceOp),
            ("RedrawWindow", ApiType::DeviceOp),
            ("UpdateWindow", ApiType::DeviceOp),
            ("GetClientRect", ApiType::Ipc),
            ("GetWindowRect", ApiType::Ipc),
            ("ClientToScreen", ApiType::Ipc),
            ("ScreenToClient", ApiType::Ipc),
            ("LoadCursorA", ApiType::ResourceOp),
            ("LoadCursorW", ApiType::ResourceOp),
            ("LoadIconA", ApiType::ResourceOp),
            ("LoadIconW", ApiType::ResourceOp),
            ("LoadImageA", ApiType::ResourceOp),
            ("LoadImageW", ApiType::ResourceOp),
            ("LoadBitmapA", ApiType::ResourceOp),
            ("LoadBitmapW", ApiType::ResourceOp),
            ("LoadMenuA", ApiType::ResourceOp),
            ("LoadMenuW", ApiType::ResourceOp),
            ("LoadAcceleratorsA", ApiType::ResourceOp),
            ("LoadAcceleratorsW", ApiType::ResourceOp),
            ("LoadStringA", ApiType::ResourceOp),
            ("LoadStringW", ApiType::ResourceOp),
        ]
    }

    /// 获取 advapi32.dll 的 API 映射
    pub fn get_advapi32_apis() -> &'static [(&'static str, ApiType)] {
        &[
            ("RegOpenKeyA", ApiType::RegistryOp),
            ("RegOpenKeyW", ApiType::RegistryOp),
            ("RegOpenKeyExA", ApiType::RegistryOp),
            ("RegOpenKeyExW", ApiType::RegistryOp),
            ("RegCreateKeyA", ApiType::RegistryOp),
            ("RegCreateKeyW", ApiType::RegistryOp),
            ("RegCreateKeyExA", ApiType::RegistryOp),
            ("RegCreateKeyExW", ApiType::RegistryOp),
            ("RegCloseKey", ApiType::RegistryOp),
            ("RegQueryValueA", ApiType::RegistryOp),
            ("RegQueryValueW", ApiType::RegistryOp),
            ("RegQueryValueExA", ApiType::RegistryOp),
            ("RegQueryValueExW", ApiType::RegistryOp),
            ("RegSetValueA", ApiType::RegistryOp),
            ("RegSetValueW", ApiType::RegistryOp),
            ("RegSetValueExA", ApiType::RegistryOp),
            ("RegSetValueExW", ApiType::RegistryOp),
            ("RegDeleteKeyA", ApiType::RegistryOp),
            ("RegDeleteKeyW", ApiType::RegistryOp),
            ("RegDeleteValueA", ApiType::RegistryOp),
            ("RegDeleteValueW", ApiType::RegistryOp),
            ("RegEnumKeyA", ApiType::RegistryOp),
            ("RegEnumKeyW", ApiType::RegistryOp),
            ("RegEnumKeyExA", ApiType::RegistryOp),
            ("RegEnumKeyExW", ApiType::RegistryOp),
            ("RegEnumValueA", ApiType::RegistryOp),
            ("RegEnumValueW", ApiType::RegistryOp),
            ("OpenProcessToken", ApiType::TokenOp),
            ("OpenThreadToken", ApiType::TokenOp),
            ("GetTokenInformation", ApiType::TokenOp),
            ("SetTokenInformation", ApiType::TokenOp),
            ("DuplicateToken", ApiType::TokenOp),
            ("DuplicateTokenEx", ApiType::TokenOp),
            ("AdjustTokenPrivileges", ApiType::PrivilegeOp),
            ("LookupPrivilegeValueA", ApiType::PrivilegeOp),
            ("LookupPrivilegeValueW", ApiType::PrivilegeOp),
            ("LookupPrivilegeNameA", ApiType::PrivilegeOp),
            ("LookupPrivilegeNameW", ApiType::PrivilegeOp),
            ("LookupPrivilegeDisplayNameA", ApiType::PrivilegeOp),
            ("LookupPrivilegeDisplayNameW", ApiType::PrivilegeOp),
            ("AllocateAndInitializeSid", ApiType::SidOp),
            ("FreeSid", ApiType::SidOp),
            ("CheckTokenMembership", ApiType::SidOp),
            ("EqualSid", ApiType::SidOp),
            ("CopySid", ApiType::SidOp),
            ("GetLengthSid", ApiType::SidOp),
            ("InitializeAcl", ApiType::AclOp),
            ("AddAccessAllowedAce", ApiType::AclOp),
            ("AddAccessDeniedAce", ApiType::AclOp),
            ("GetSecurityDescriptorLength", ApiType::SecurityDescriptorOp),
            ("InitializeSecurityDescriptor", ApiType::SecurityDescriptorOp),
            ("GetSecurityDescriptorDacl", ApiType::SecurityDescriptorOp),
            ("SetSecurityDescriptorDacl", ApiType::SecurityDescriptorOp),
            ("CryptAcquireContextA", ApiType::CryptoApiOp),
            ("CryptAcquireContextW", ApiType::CryptoApiOp),
            ("CryptReleaseContext", ApiType::CryptoApiOp),
            ("CryptGenKey", ApiType::CryptoApiOp),
            ("CryptDestroyKey", ApiType::CryptoApiOp),
            ("CryptExportKey", ApiType::CryptoApiOp),
            ("CryptImportKey", ApiType::CryptoApiOp),
            ("CryptEncrypt", ApiType::CryptoApiOp),
            ("CryptDecrypt", ApiType::CryptoApiOp),
            ("CryptCreateHash", ApiType::CryptoApiOp),
            ("CryptHashData", ApiType::CryptoApiOp),
            ("CryptDestroyHash", ApiType::CryptoApiOp),
            ("CryptSignHashA", ApiType::CryptoApiOp),
            ("CryptSignHashW", ApiType::CryptoApiOp),
            ("CryptVerifySignatureA", ApiType::CryptoApiOp),
            ("CryptVerifySignatureW", ApiType::CryptoApiOp),
            ("CryptGenRandom", ApiType::Random),
            ("CryptGetHashParam", ApiType::CryptoApiOp),
            ("CryptSetHashParam", ApiType::CryptoApiOp),
            ("CryptGetKeyParam", ApiType::CryptoApiOp),
            ("CryptSetKeyParam", ApiType::CryptoApiOp),
            ("CryptGetProvParam", ApiType::CryptoApiOp),
            ("CryptSetProvParam", ApiType::CryptoApiOp),
            ("CryptEnumProvidersA", ApiType::CryptoApiOp),
            ("CryptEnumProvidersW", ApiType::CryptoApiOp),
            ("CryptEnumProviderTypesA", ApiType::CryptoApiOp),
            ("CryptEnumProviderTypesW", ApiType::CryptoApiOp),
            ("CryptContextAddRef", ApiType::CryptoApiOp),
            ("CryptDuplicateKey", ApiType::CryptoApiOp),
            ("CryptDuplicateHash", ApiType::CryptoApiOp),
            ("CryptGetDefaultProviderA", ApiType::CryptoApiOp),
            ("CryptGetDefaultProviderW", ApiType::CryptoApiOp),
            ("CryptSetProviderA", ApiType::CryptoApiOp),
            ("CryptSetProviderW", ApiType::CryptoApiOp),
            ("CryptSetProviderExA", ApiType::CryptoApiOp),
            ("CryptSetProviderExW", ApiType::CryptoApiOp),
            ("CryptSignHash", ApiType::CryptoApiOp),
            ("CryptVerifySignature", ApiType::CryptoApiOp),
            ("StartServiceA", ApiType::ServiceOp),
            ("StartServiceW", ApiType::ServiceOp),
            ("StartServiceCtrlDispatcherA", ApiType::ServiceOp),
            ("StartServiceCtrlDispatcherW", ApiType::ServiceOp),
            ("ControlService", ApiType::ServiceOp),
            ("CreateServiceA", ApiType::ServiceOp),
            ("CreateServiceW", ApiType::ServiceOp),
            ("DeleteService", ApiType::ServiceOp),
            ("EnumServicesStatusA", ApiType::ServiceOp),
            ("EnumServicesStatusW", ApiType::ServiceOp),
            ("EnumServicesStatusExA", ApiType::ServiceOp),
            ("EnumServicesStatusExW", ApiType::ServiceOp),
            ("GetServiceDisplayNameA", ApiType::ServiceOp),
            ("GetServiceDisplayNameW", ApiType::ServiceOp),
            ("GetServiceKeyNameA", ApiType::ServiceOp),
            ("GetServiceKeyNameW", ApiType::ServiceOp),
            ("LockServiceDatabase", ApiType::ServiceOp),
            ("NotifyBootConfigStatus", ApiType::ServiceOp),
            ("OpenSCManagerA", ApiType::ServiceOp),
            ("OpenSCManagerW", ApiType::ServiceOp),
            ("OpenServiceA", ApiType::ServiceOp),
            ("OpenServiceW", ApiType::ServiceOp),
            ("QueryServiceConfigA", ApiType::ServiceOp),
            ("QueryServiceConfigW", ApiType::ServiceOp),
            ("QueryServiceConfig2A", ApiType::ServiceOp),
            ("QueryServiceConfig2W", ApiType::ServiceOp),
            ("QueryServiceLockStatusA", ApiType::ServiceOp),
            ("QueryServiceLockStatusW", ApiType::ServiceOp),
            ("QueryServiceObjectSecurity", ApiType::ServiceOp),
            ("QueryServiceStatus", ApiType::ServiceOp),
            ("QueryServiceStatusEx", ApiType::ServiceOp),
            ("RegisterServiceCtrlHandlerA", ApiType::ServiceOp),
            ("RegisterServiceCtrlHandlerW", ApiType::ServiceOp),
            ("RegisterServiceCtrlHandlerExA", ApiType::ServiceOp),
            ("RegisterServiceCtrlHandlerExW", ApiType::ServiceOp),
            ("SetServiceObjectSecurity", ApiType::ServiceOp),
            ("SetServiceStatus", ApiType::ServiceOp),
            ("UnlockServiceDatabase", ApiType::ServiceOp),
            ("ChangeServiceConfigA", ApiType::ServiceOp),
            ("ChangeServiceConfigW", ApiType::ServiceOp),
            ("ChangeServiceConfig2A", ApiType::ServiceOp),
            ("ChangeServiceConfig2W", ApiType::ServiceOp),
            ("NotifyServiceStatusChangeA", ApiType::ServiceOp),
            ("NotifyServiceStatusChangeW", ApiType::ServiceOp),
            ("ControlServiceExA", ApiType::ServiceOp),
            ("ControlServiceExW", ApiType::ServiceOp),
            ("EnumDependentServicesA", ApiType::ServiceOp),
            ("EnumDependentServicesW", ApiType::ServiceOp),
        ]
    }

    /// 查找 API 类型
    pub fn lookup_api_type(dll_name: &str, func_name: &str) -> ApiType {
        let dll_lower = dll_name.to_lowercase();
        let func_lower = func_name.to_lowercase();

        // 根据 DLL 名称选择对应的 API 列表
        let apis: &[(&str, ApiType)] = match dll_lower.as_str() {
            "kernel32.dll" | "kernelbase.dll" => Self::get_kernel32_apis(),
            "ntdll.dll" => Self::get_ntdll_apis(),
            "user32.dll" | "userbase.dll" => Self::get_user32_apis(),
            "advapi32.dll" => Self::get_advapi32_apis(),
            _ => &[],
        };

        // 查找函数
        for (name, api_type) in apis {
            if name.to_lowercase() == func_lower {
                return *api_type;
            }
        }

        ApiType::None
    }

    /// 检查是否是敏感 API（需要特殊处理）
    pub fn is_sensitive_api(dll_name: &str, func_name: &str) -> bool {
        let api_type = Self::lookup_api_type(dll_name, func_name);
        api_type.is_security_related() || api_type.is_debug_related()
    }

    /// 检查是否是内存相关的 API
    pub fn is_memory_api(dll_name: &str, func_name: &str) -> bool {
        let api_type = Self::lookup_api_type(dll_name, func_name);
        api_type.is_memory_related()
    }
}

/// SDK 函数信息
#[derive(Debug, Clone)]
pub struct SdkFunction {
    pub name: String,
    pub address: u64,
    pub compilation_type: CompilationType,
}

impl SdkFunction {
    pub fn new(name: String, address: u64, compilation_type: CompilationType) -> Self {
        Self {
            name,
            address,
            compilation_type,
        }
    }
}

/// SDK 导入信息
#[derive(Debug, Clone)]
pub struct SdkImport {
    pub dll_name: String,
    pub functions: Vec<SdkFunction>,
}

impl SdkImport {
    pub fn new(dll_name: String) -> Self {
        Self {
            dll_name,
            functions: Vec::new(),
        }
    }

    pub fn add_function(&mut self, func: SdkFunction) {
        self.functions.push(func);
    }
}

/// SDK 导入列表
#[derive(Debug, Clone)]
pub struct SdkImportList {
    imports: Vec<SdkImport>,
}

impl SdkImportList {
    pub fn new() -> Self {
        Self {
            imports: Vec::new(),
        }
    }

    /// 添加 SDK 导入
    pub fn add_import(&mut self, import: SdkImport) {
        self.imports.push(import);
    }

    /// 添加 SDK 函数
    pub fn add_sdk_function(&mut self, dll: &str, func: &str, addr: u64, compilation_type: CompilationType) {
        let func_info = SdkFunction::new(func.to_string(), addr, compilation_type);
        
        // 查找或创建导入
        if let Some(import) = self.imports.iter_mut().find(|i| i.dll_name == dll) {
            import.add_function(func_info);
        } else {
            let mut new_import = SdkImport::new(dll.to_string());
            new_import.add_function(func_info);
            self.imports.push(new_import);
        }
    }

    /// 检查是否有 SDK 导入
    pub fn has_sdk(&self) -> bool {
        !self.imports.is_empty()
    }

    /// 获取 SDK 信息
    pub fn get_sdk_info(&self, name: &str) -> Option<&SdkImport> {
        self.imports.iter().find(|i| i.dll_name == name)
    }

    /// 获取所有导入
    pub fn imports(&self) -> &[SdkImport] {
        &self.imports
    }

    /// 获取函数总数
    pub fn total_functions(&self) -> usize {
        self.imports.iter().map(|i| i.functions.len()).sum()
    }

    /// 清空所有导入
    pub fn clear(&mut self) {
        self.imports.clear();
    }
}

impl Default for SdkImportList {
    fn default() -> Self {
        Self::new()
    }
}

/// 函数映射列表
#[derive(Debug, Clone)]
pub struct MapFunctionList {
    functions: Vec<MapFunction>,
    by_name: HashMap<String, usize>,
    by_address: HashMap<u64, usize>,
}

impl MapFunctionList {
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
            by_name: HashMap::new(),
            by_address: HashMap::new(),
        }
    }

    /// 添加函数映射
    pub fn add(&mut self, func: MapFunction) {
        let index = self.functions.len();
        self.by_name.insert(func.full_name(), index);
        self.by_address.insert(func.address, index);
        self.functions.push(func);
    }

    /// 通过名称查找
    pub fn find_by_name(&self, full_name: &str) -> Option<&MapFunction> {
        self.by_name.get(full_name).map(|&idx| &self.functions[idx])
    }

    /// 通过地址查找
    pub fn find_by_address(&self, address: u64) -> Option<&MapFunction> {
        self.by_address.get(&address).map(|&idx| &self.functions[idx])
    }

    /// 通过 DLL 名称查找所有函数
    pub fn find_by_dll(&self, dll_name: &str) -> Vec<&MapFunction> {
        self.functions.iter().filter(|f| f.dll_name == dll_name).collect()
    }

    /// 通过 API 类型查找
    pub fn find_by_api_type(&self, api_type: ApiType) -> Vec<&MapFunction> {
        self.functions.iter().filter(|f| f.api_type == api_type).collect()
    }

    /// 获取所有函数
    pub fn functions(&self) -> &[MapFunction] {
        &self.functions
    }

    /// 获取函数数量
    pub fn count(&self) -> usize {
        self.functions.len()
    }

    /// 清空所有函数
    pub fn clear(&mut self) {
        self.functions.clear();
        self.by_name.clear();
        self.by_address.clear();
    }

    /// 批量添加函数
    pub fn add_batch(&mut self, functions: Vec<MapFunction>) {
        for func in functions {
            self.add(func);
        }
    }

    /// 从导入列表构建
    pub fn from_imports<I>(imports: I) -> Self
    where
        I: Iterator<Item = (String, String, Option<u16>)>,
    {
        let mut list = Self::new();
        
        for (dll_name, func_name, ordinal) in imports {
            let map_func = if let Some(ord) = ordinal {
                MapFunction::from_ordinal(&dll_name, ord)
            } else {
                MapFunction::from_name(&dll_name, &func_name)
            };
            
            if let Some(func) = map_func {
                list.add(func);
            }
        }
        
        list
    }
}

impl Default for MapFunctionList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_type_from_u32() {
        assert_eq!(ApiType::from_u32(0), ApiType::None);
        assert_eq!(ApiType::from_u32(1), ApiType::MemoryRead);
        assert_eq!(ApiType::from_u32(100), ApiType::SecurityDescriptorOp);
    }

    #[test]
    fn test_api_type_is_security_related() {
        assert!(ApiType::CryptoOp.is_security_related());
        assert!(ApiType::Encryption.is_security_related());
        assert!(!ApiType::MemoryRead.is_security_related());
    }

    #[test]
    fn test_compilation_type() {
        assert!(CompilationType::Virtualized.needs_virtualization());
        assert!(CompilationType::Ultra.needs_virtualization());
        assert!(!CompilationType::Default.needs_virtualization());
    }

    #[test]
    fn test_map_function() {
        let func = MapFunction::new("TestFunc".to_string(), "test.dll".to_string())
            .with_api_type(ApiType::FileOp)
            .with_compilation_type(CompilationType::Virtualized)
            .with_address(0x1000)
            .with_sdk(true);

        assert_eq!(func.name, "TestFunc");
        assert_eq!(func.dll_name, "test.dll");
        assert_eq!(func.api_type, ApiType::FileOp);
        assert_eq!(func.compilation_type, CompilationType::Virtualized);
        assert_eq!(func.address, 0x1000);
        assert!(func.is_sdk);
        assert_eq!(func.full_name(), "test.dll!TestFunc");
    }

    #[test]
    fn test_map_function_from_name() {
        let func = MapFunction::from_name("kernel32.dll", "ReadProcessMemory").unwrap();
        assert_eq!(func.api_type, ApiType::MemoryRead);
    }

    #[test]
    fn test_map_function_options() {
        let mut func = MapFunction::new("Test".to_string(), "test.dll".to_string());
        func.include_option(ImportOption::PROTECTED);
        func.include_option(ImportOption::HIDDEN);
        
        assert!(func.has_option(ImportOption::PROTECTED));
        assert!(func.has_option(ImportOption::HIDDEN));
        assert!(!func.has_option(ImportOption::ENCRYPTED));
        
        func.exclude_option(ImportOption::HIDDEN);
        assert!(!func.has_option(ImportOption::HIDDEN));
    }

    #[test]
    fn test_database_lookup() {
        assert_eq!(
            MapFunctionDatabase::lookup_api_type("kernel32.dll", "ReadProcessMemory"),
            ApiType::MemoryRead
        );
        assert_eq!(
            MapFunctionDatabase::lookup_api_type("ntdll.dll", "NtReadVirtualMemory"),
            ApiType::MemoryRead
        );
        assert_eq!(
            MapFunctionDatabase::lookup_api_type("unknown.dll", "UnknownFunc"),
            ApiType::None
        );
    }

    #[test]
    fn test_database_is_sensitive() {
        assert!(MapFunctionDatabase::is_sensitive_api("kernel32.dll", "IsDebuggerPresent"));
        assert!(!MapFunctionDatabase::is_sensitive_api("kernel32.dll", "Sleep"));
    }

    #[test]
    fn test_sdk_import_list() {
        let mut list = SdkImportList::new();
        list.add_sdk_function("kernel32.dll", "TestFunc", 0x1000, CompilationType::Virtualized);
        
        assert!(list.has_sdk());
        assert_eq!(list.total_functions(), 1);
        
        let info = list.get_sdk_info("kernel32.dll");
        assert!(info.is_some());
        assert_eq!(info.unwrap().functions.len(), 1);
    }

    #[test]
    fn test_map_function_list() {
        let mut list = MapFunctionList::new();
        
        let func1 = MapFunction::new("Func1".to_string(), "dll1.dll".to_string());
        let func2 = MapFunction::new("Func2".to_string(), "dll2.dll".to_string());
        
        list.add(func1);
        list.add(func2);
        
        assert_eq!(list.count(), 2);
        
        let found = list.find_by_name("dll1.dll!Func1");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Func1");
    }
}
