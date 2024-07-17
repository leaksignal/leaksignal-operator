
fn ganesha_template(service_ip: &str) -> String {
    format!(r#"
LOG {{
    Default_Log_Level = INFO;

    Components {{
        #ALL = DEBUG;
        MEMLEAKS = FATAL;
        FSAL = FULL_DEBUG;
        NFSPROTO = FATAL;
        NFS_V4 = FATAL;
        EXPORT = FATAL;
        FILEHANDLE = FATAL;
        DISPATCH = FATAL;
        CACHE_INODE = FATAL;
        CACHE_INODE_LRU = FATAL;
        HASHTABLE = FATAL;
        HASHTABLE_CACHE = FATAL;
        DUPREQ = FATAL;
        INIT = DEBUG;
        MAIN = DEBUG;
        IDMAPPER = FATAL;
        NFS_READDIR = FATAL;
        NFS_V4_LOCK = FATAL;
        CONFIG = FATAL;
        CLIENTID = FATAL;
        SESSIONS = FATAL;
        PNFS = FATAL;
        RW_LOCK = FATAL;
        NLM = FATAL;
        RPC = FATAL;
        NFS_CB = FATAL;
        THREAD = FATAL;
        NFS_V4_ACL = FATAL;
        STATE = FATAL;
        FSAL_UP = FATAL;
        DBUS = FATAL;
    }}

    Format {{
        date_format = ISO-8601;
        time_format = ISO-8601;
        EPOCH = FALSE;
        CLIENTIP = TRUE;
        HOSTNAME = TRUE;
        PID = FALSE;
        THREAD_NAME = FALSE;
        FILE_NAME = FALSE;
        LINE_NUM = FALSE;
        FUNCTION_NAME = FALSE;
        COMPONENT = TRUE;
        LEVEL = TRUE;
    }}
}}

NFS_Core_Param
{{
    Bind_addr=0.0.0.0;
    MNT_Port = 20048;
    NLM_Port = 32803;
    fsid_device = true;
}}

NFSV4 {{
    Graceless = false;
    Grace_Period = 90;
    Allow_Numeric_Owners = true;
    Only_Numeric_Owners = true;
}}

EXPORT {{
    # Export Id (mandatory, each EXPORT must have a unique Export_Id)
    Export_Id = 0;

    # Exported path (mandatory)
    Path = "/";

    # Pseudo Path (required for NFS v4)
    Pseudo = "/";

    # Access control options
    Access_Type = NONE;
    #Access_Type = RO;
    Squash = allsquash;

    # NFS protocol options
    Transports = UDP, TCP;
    Protocols = 4;
    SecType = sys;
    Disable_ACL = false;
    
    # changed to false, otherwise normal users can't access directories where gid=0
    Manage_Gids = false;

    #to test disable getattr cache
    #Attr_Expiration_Time = 0;

    Anonymous_uid = 65534;
    Anonymous_gid = 65534;

    CLIENT {{
        Clients = 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16;
        Access_Type = RO;
    }}

    Filesystem_id = 1.1;
    
    # Exporting FSAL
    FSAL {{
        Name = PROXY_V3;
        Srv_Addr = {service_ip};
    }}
}}
"#)
}

pub async fn write_ganesha_config(service_ip: &str) -> std::io::Result<()> {
    tokio::fs::write(r"/etc/ganesha/ganesha.conf", ganesha_template(service_ip)).await
}