import Foundation

// MS-RDPEFS file-system (drive) redirection: shares a local folder as a drive in the remote session.
// The server sends DR_DEVICE_IOREQUEST PDUs (major function + a per-function body); we map each to a
// FileManager operation on the shared folder and reply with a DR_DEVICE_IOCOMPLETION (NTSTATUS + a
// per-function body). Byte layouts follow MS-RDPEFS / MS-FSCC. Local fork addition (see FORK.md).

enum RDPDriveMajorFunction {
    static let create: UInt32 = 0x0000_0000
    static let close: UInt32 = 0x0000_0002
    static let read: UInt32 = 0x0000_0003
    static let write: UInt32 = 0x0000_0004
    static let queryInformation: UInt32 = 0x0000_0005
    static let setInformation: UInt32 = 0x0000_0006
    static let queryVolumeInformation: UInt32 = 0x0000_000A
    static let setVolumeInformation: UInt32 = 0x0000_000B
    static let directoryControl: UInt32 = 0x0000_000C
    static let deviceControl: UInt32 = 0x0000_000E
    static let lockControl: UInt32 = 0x0000_0011
}

enum RDPDriveMinorFunction {
    static let queryDirectory: UInt32 = 0x0000_0001
    static let notifyChangeDirectory: UInt32 = 0x0000_0002
}

enum RDPDriveStatus {
    static let success: UInt32 = 0x0000_0000
    static let noMoreFiles: UInt32 = 0x8000_0006
    static let unsuccessful: UInt32 = 0xC000_0001
    static let notImplemented: UInt32 = 0xC000_0002
    static let endOfFile: UInt32 = 0xC000_0011
    static let accessDenied: UInt32 = 0xC000_0022
    static let objectNameNotFound: UInt32 = 0xC000_0034
    static let objectNameCollision: UInt32 = 0xC000_0035
    static let objectPathNotFound: UInt32 = 0xC000_003A
    static let notSupported: UInt32 = 0xC000_00BB
    static let directoryNotEmpty: UInt32 = 0xC000_0101
    static let notADirectory: UInt32 = 0xC000_0103
}

enum RDPDriveFileAttribute {
    static let readonly: UInt32 = 0x0000_0001
    static let hidden: UInt32 = 0x0000_0002
    static let directory: UInt32 = 0x0000_0010
    static let archive: UInt32 = 0x0000_0020
    static let normal: UInt32 = 0x0000_0080
}

private enum RDPDriveCreateDisposition {
    static let supersede: UInt32 = 0
    static let open: UInt32 = 1
    static let create: UInt32 = 2
    static let openIf: UInt32 = 3
    static let overwrite: UInt32 = 4
    static let overwriteIf: UInt32 = 5
}

private enum RDPDriveCreateOptions {
    static let directoryFile: UInt32 = 0x0000_0001
    static let nonDirectoryFile: UInt32 = 0x0000_0040
    static let deleteOnClose: UInt32 = 0x0000_1000
}

private enum RDPDriveCreateInformation {
    static let superseded: UInt8 = 0
    static let opened: UInt8 = 1
    static let created: UInt8 = 2
    static let overwritten: UInt8 = 3
}

private enum RDPDriveFsInformationClass {
    static let fileDirectoryInformation: UInt32 = 1
    static let fileFullDirectoryInformation: UInt32 = 2
    static let fileBothDirectoryInformation: UInt32 = 3
    static let fileBasicInformation: UInt32 = 4
    static let fileStandardInformation: UInt32 = 5
    static let fileNamesInformation: UInt32 = 12
    static let fileRenameInformation: UInt32 = 10
    static let fileDispositionInformation: UInt32 = 13
    static let fileAllocationInformation: UInt32 = 19
    static let fileEndOfFileInformation: UInt32 = 20
    static let fileAttributeTagInformation: UInt32 = 35
}

private enum RDPDriveFsVolumeClass {
    static let volumeInformation: UInt32 = 1
    static let sizeInformation: UInt32 = 3
    static let deviceInformation: UInt32 = 4
    static let attributeInformation: UInt32 = 5
    static let fullSizeInformation: UInt32 = 7
}

/// The parsed common header of a Device I/O Request (MS-RDPEFS 2.2.1.4).
struct RDPDriveIORequest: Sendable {
    var deviceID: UInt32
    var fileID: UInt32
    var completionID: UInt32
    var majorFunction: UInt32
    var minorFunction: UInt32

    static func parse(from cursor: inout ByteCursor) throws -> RDPDriveIORequest {
        try RDPDriveIORequest(
            deviceID: cursor.readLittleEndianUInt32(),
            fileID: cursor.readLittleEndianUInt32(),
            completionID: cursor.readLittleEndianUInt32(),
            majorFunction: cursor.readLittleEndianUInt32(),
            minorFunction: cursor.readLittleEndianUInt32()
        )
    }
}

/// Serves one shared folder as a redirected drive. Not thread-safe on its own; the owning
/// device-redirection session serializes calls (`handle`) on the NIO event loop.
final class RDPDriveShare {
    let rootURL: URL
    let label: String
    private let fileManager = FileManager.default

    private struct OpenFile {
        var url: URL
        var isDirectory: Bool
        var deleteOnClose: Bool
        var handle: FileHandle?
        var enumeration: [URL]?     // directory listing, built on the initial query
        var enumIndex: Int
    }

    private var openFiles: [UInt32: OpenFile] = [:]
    private var nextFileID: UInt32 = 1

    init(path: String, label: String) {
        // Symlinks are resolved here as well as in `resolve(_:)`, and both must agree: on macOS the
        // root itself is often behind one (/tmp -> /private/tmp, /var -> /private/var), so comparing
        // a resolved child against an unresolved root would reject perfectly legitimate paths.
        rootURL = URL(fileURLWithPath: path, isDirectory: true)
            .standardizedFileURL
            .resolvingSymlinksInPath()
        self.label = label.isEmpty ? "Shared" : label
    }

    /// Handle one request; returns the IoStatus + the per-function completion body (after IoStatus).
    func handle(_ request: RDPDriveIORequest, body: inout ByteCursor) -> (status: UInt32, payload: Data) {
        switch request.majorFunction {
        case RDPDriveMajorFunction.create: return create(&body)
        case RDPDriveMajorFunction.close: return close(request.fileID)
        case RDPDriveMajorFunction.read: return read(request.fileID, &body)
        case RDPDriveMajorFunction.write: return write(request.fileID, &body)
        case RDPDriveMajorFunction.queryInformation: return queryInformation(request.fileID, &body)
        case RDPDriveMajorFunction.setInformation: return setInformation(request.fileID, &body)
        case RDPDriveMajorFunction.queryVolumeInformation: return queryVolume(&body)
        case RDPDriveMajorFunction.directoryControl:
            return request.minorFunction == RDPDriveMinorFunction.queryDirectory
                ? queryDirectory(request.fileID, &body)
                : (RDPDriveStatus.notSupported, Data())   // notify-change: no live refresh in v1
        case RDPDriveMajorFunction.lockControl: return (RDPDriveStatus.success, Data())
        default: return (RDPDriveStatus.notImplemented, Data())
        }
    }

    /// Close all handles (on channel teardown).
    func reset() {
        for file in openFiles.values { try? file.handle?.close() }
        openFiles.removeAll()
    }

    // MARK: - Path mapping

    /// Map a remote (backslash) path under the share to a local URL, rejecting escapes ("..").
    private func resolve(_ remotePath: String) -> URL? {
        let components = remotePath
            .replacingOccurrences(of: "\\", with: "/")
            .split(separator: "/")
            .map(String.init)
        guard components.contains("..") == false, components.contains(".") == false else { return nil }
        var url = rootURL
        for component in components { url.appendPathComponent(component) }
        // `standardizedFileURL` only normalises the path lexically - it does not follow symbolic
        // links, and FileHandle/FileManager do. Without `resolvingSymlinksInPath()` a link placed
        // inside the shared folder (deliberately, or simply because the user shared a directory that
        // already contains one) lets the remote read and write anywhere that link points.
        url = url.standardizedFileURL.resolvingSymlinksInPath()
        // Must remain within the share root.
        let rootPath = rootURL.path.hasSuffix("/") ? rootURL.path : rootURL.path + "/"
        guard url.path == rootURL.path || url.path.hasPrefix(rootPath) else { return nil }
        return url
    }

    /// Test seam: the path guard is the security boundary of a redirected drive, and every input to
    /// it comes from the remote, so it is exercised directly rather than through an I/O request.
    func resolveForTesting(_ remotePath: String) -> URL? { resolve(remotePath) }

    // MARK: - CREATE

    private func create(_ body: inout ByteCursor) -> (UInt32, Data) {
        guard
            let desiredAccess = try? body.readLittleEndianUInt32(),
            let _ = try? body.readLittleEndianUInt64(),          // AllocationSize
            let _ = try? body.readLittleEndianUInt32(),          // FileAttributes
            let _ = try? body.readLittleEndianUInt32(),          // SharedAccess
            let disposition = try? body.readLittleEndianUInt32(),
            let options = try? body.readLittleEndianUInt32(),
            let pathLength = try? body.readLittleEndianUInt32(),
            let pathData = try? body.readData(count: Int(pathLength))
        else { return failure() }
        _ = desiredAccess

        let remotePath = decodeUTF16(pathData)
        guard let url = resolve(remotePath) else {
            return (RDPDriveStatus.accessDenied, createBody(fileID: 0, information: 0))
        }

        let existed = fileManager.fileExists(atPath: url.path)
        var isDir = existsDirectory(url)
        let wantsDirectory = options & RDPDriveCreateOptions.directoryFile != 0

        switch disposition {
        case RDPDriveCreateDisposition.open:
            guard existed else { return (RDPDriveStatus.objectNameNotFound, createBody(fileID: 0, information: 0)) }
        case RDPDriveCreateDisposition.create:
            guard existed == false else { return (RDPDriveStatus.objectNameCollision, createBody(fileID: 0, information: 0)) }
            guard makeItem(at: url, directory: wantsDirectory) else { return failure() }
            isDir = wantsDirectory
        case RDPDriveCreateDisposition.openIf:
            if existed == false {
                guard makeItem(at: url, directory: wantsDirectory) else { return failure() }
                isDir = wantsDirectory
            }
        case RDPDriveCreateDisposition.overwrite:
            guard existed, isDir == false else { return (RDPDriveStatus.objectNameNotFound, createBody(fileID: 0, information: 0)) }
            fileManager.createFile(atPath: url.path, contents: Data())
        case RDPDriveCreateDisposition.overwriteIf, RDPDriveCreateDisposition.supersede:
            if isDir == false { fileManager.createFile(atPath: url.path, contents: Data()) }
        default:
            return failure()
        }

        var handle: FileHandle?
        if isDir == false {
            handle = try? FileHandle(forUpdating: url)
            if handle == nil { handle = try? FileHandle(forReadingFrom: url) }   // read-only files
        }
        let fileID = allocateFileID()
        openFiles[fileID] = OpenFile(
            url: url, isDirectory: isDir,
            deleteOnClose: options & RDPDriveCreateOptions.deleteOnClose != 0,
            handle: handle, enumeration: nil, enumIndex: 0
        )
        let information: UInt8 = existed ? RDPDriveCreateInformation.opened : RDPDriveCreateInformation.created
        return (RDPDriveStatus.success, createBody(fileID: fileID, information: information))
    }

    private func createBody(fileID: UInt32, information: UInt8) -> Data {
        var data = Data()
        data.appendLittleEndianUInt32(fileID)
        data.appendUInt8(information)
        return data
    }

    // MARK: - CLOSE

    private func close(_ fileID: UInt32) -> (UInt32, Data) {
        if let file = openFiles.removeValue(forKey: fileID) {
            try? file.handle?.close()
            if file.deleteOnClose { try? fileManager.removeItem(at: file.url) }
        }
        return (RDPDriveStatus.success, Data(count: 5))   // Padding (5 bytes)
    }

    // MARK: - READ / WRITE

    private func read(_ fileID: UInt32, _ body: inout ByteCursor) -> (UInt32, Data) {
        guard let length = try? body.readLittleEndianUInt32(),
              let offset = try? body.readLittleEndianUInt64(),
              let file = openFiles[fileID], let handle = file.handle
        else { return failure() }
        do {
            try handle.seek(toOffset: offset)
            let data = handle.readData(ofLength: Int(length))
            var payload = Data()
            payload.appendLittleEndianUInt32(UInt32(data.count))
            payload.append(data)
            return (RDPDriveStatus.success, payload)
        } catch {
            return failure()
        }
    }

    private func write(_ fileID: UInt32, _ body: inout ByteCursor) -> (UInt32, Data) {
        guard let length = try? body.readLittleEndianUInt32(),
              let offset = try? body.readLittleEndianUInt64(),
              let _ = try? body.readData(count: 20),                 // Padding
              let data = try? body.readData(count: Int(length)),
              let file = openFiles[fileID], let handle = file.handle
        else { return failure() }
        do {
            try handle.seek(toOffset: offset)
            handle.write(data)
            var payload = Data()
            payload.appendLittleEndianUInt32(UInt32(data.count))
            payload.appendUInt8(0)                                   // Padding
            return (RDPDriveStatus.success, payload)
        } catch {
            return failure()
        }
    }

    // MARK: - QUERY / SET INFORMATION

    private func queryInformation(_ fileID: UInt32, _ body: inout ByteCursor) -> (UInt32, Data) {
        guard let infoClass = try? body.readLittleEndianUInt32(),
              let file = openFiles[fileID] else { return failure() }
        let attributes = try? fileManager.attributesOfItem(atPath: file.url.path)
        let size = (attributes?[.size] as? UInt64) ?? 0
        let created = attributes?[.creationDate] as? Date
        let modified = attributes?[.modificationDate] as? Date

        var buffer = Data()
        switch infoClass {
        case RDPDriveFsInformationClass.fileBasicInformation:
            buffer.appendLittleEndianUInt64(fileTime(created))
            buffer.appendLittleEndianUInt64(fileTime(modified))
            buffer.appendLittleEndianUInt64(fileTime(modified))
            buffer.appendLittleEndianUInt64(fileTime(modified))
            buffer.appendLittleEndianUInt32(fileAttributes(file.url, isDirectory: file.isDirectory))
            buffer.appendLittleEndianUInt32(0)
        case RDPDriveFsInformationClass.fileStandardInformation:
            buffer.appendLittleEndianUInt64(size)                   // AllocationSize
            buffer.appendLittleEndianUInt64(size)                   // EndOfFile
            buffer.appendLittleEndianUInt32(1)                      // NumberOfLinks
            buffer.appendUInt8(0)                                   // DeletePending
            buffer.appendUInt8(file.isDirectory ? 1 : 0)           // Directory
            buffer.appendLittleEndianUInt16(0)                     // Reserved
        case RDPDriveFsInformationClass.fileAttributeTagInformation:
            buffer.appendLittleEndianUInt32(fileAttributes(file.url, isDirectory: file.isDirectory))
            buffer.appendLittleEndianUInt32(0)                     // ReparseTag
        default:
            return (RDPDriveStatus.notSupported, lengthPrefixed(Data()))
        }
        return (RDPDriveStatus.success, lengthPrefixed(buffer))
    }

    private func setInformation(_ fileID: UInt32, _ body: inout ByteCursor) -> (UInt32, Data) {
        guard let infoClass = try? body.readLittleEndianUInt32(),
              let length = try? body.readLittleEndianUInt32(),
              let _ = try? body.readData(count: 24),                 // Padding
              let payload = try? body.readData(count: Int(length)),
              let file = openFiles[fileID] else { return failure() }

        switch infoClass {
        case RDPDriveFsInformationClass.fileDispositionInformation:
            // Any non-empty request marks delete-on-close (DeletePending flag).
            openFiles[fileID]?.deleteOnClose = payload.first.map { $0 != 0 } ?? true
        case RDPDriveFsInformationClass.fileEndOfFileInformation,
             RDPDriveFsInformationClass.fileAllocationInformation:
            var cursor = ByteCursor(payload)
            if let newSize = try? cursor.readLittleEndianUInt64() {
                try? file.handle?.truncate(atOffset: newSize)
            }
        case RDPDriveFsInformationClass.fileRenameInformation:
            guard rename(file: file, fileID: fileID, request: payload) else { return failure() }
        case RDPDriveFsInformationClass.fileBasicInformation:
            break   // times/attributes: accept but don't apply
        default:
            return (RDPDriveStatus.notSupported, lengthPrefixed(Data()))
        }
        return (RDPDriveStatus.success, lengthPrefixed(Data()))
    }

    private func rename(file: OpenFile, fileID: UInt32, request: Data) -> Bool {
        var cursor = ByteCursor(request)
        // FILE_RENAME_INFORMATION: ReplaceIfExists(1), RootDirectory(8), FileNameLength(4), FileName[]
        guard let replace = try? cursor.readUInt8(),
              let _ = try? cursor.readData(count: 8),
              let nameLength = try? cursor.readLittleEndianUInt32(),
              let nameData = try? cursor.readData(count: Int(nameLength)),
              let target = resolve(decodeUTF16(nameData)) else { return false }
        if fileManager.fileExists(atPath: target.path) {
            guard replace != 0 else { return false }
            try? fileManager.removeItem(at: target)
        }
        do {
            try fileManager.moveItem(at: file.url, to: target)
            openFiles[fileID]?.url = target
            return true
        } catch {
            return false
        }
    }

    // MARK: - QUERY VOLUME INFORMATION

    private func queryVolume(_ body: inout ByteCursor) -> (UInt32, Data) {
        guard let infoClass = try? body.readLittleEndianUInt32() else { return failure() }
        var buffer = Data()
        switch infoClass {
        case RDPDriveFsVolumeClass.volumeInformation:
            let name = utf16LE(label)
            buffer.appendLittleEndianUInt64(0)                     // VolumeCreationTime
            buffer.appendLittleEndianUInt32(0x1234_5678)          // VolumeSerialNumber
            buffer.appendLittleEndianUInt32(UInt32(name.count))   // VolumeLabelLength
            buffer.appendUInt8(0)                                  // SupportsObjects
            buffer.appendUInt8(0)                                  // Reserved
            buffer.append(name)
        case RDPDriveFsVolumeClass.sizeInformation:
            let (total, available) = volumeCapacity()
            buffer.appendLittleEndianUInt64(total)                // TotalAllocationUnits
            buffer.appendLittleEndianUInt64(available)            // AvailableAllocationUnits
            buffer.appendLittleEndianUInt32(1)                    // SectorsPerAllocationUnit
            buffer.appendLittleEndianUInt32(512)                  // BytesPerSector
        case RDPDriveFsVolumeClass.fullSizeInformation:
            let (total, available) = volumeCapacity()
            buffer.appendLittleEndianUInt64(total)                // TotalAllocationUnits
            buffer.appendLittleEndianUInt64(available)            // CallerAvailableAllocationUnits
            buffer.appendLittleEndianUInt64(available)            // ActualAvailableAllocationUnits
            buffer.appendLittleEndianUInt32(1)                    // SectorsPerAllocationUnit
            buffer.appendLittleEndianUInt32(512)                  // BytesPerSector
        case RDPDriveFsVolumeClass.deviceInformation:
            buffer.appendLittleEndianUInt32(0x0000_0007)          // FILE_DEVICE_DISK
            buffer.appendLittleEndianUInt32(0)                    // Characteristics
        case RDPDriveFsVolumeClass.attributeInformation:
            let name = utf16LE("RDPKitFS")
            buffer.appendLittleEndianUInt32(0x0000_0002)          // FILE_CASE_PRESERVED_NAMES
            buffer.appendLittleEndianUInt32(255)                  // MaximumComponentNameLength
            buffer.appendLittleEndianUInt32(UInt32(name.count))   // FileSystemNameLength
            buffer.append(name)
        default:
            return (RDPDriveStatus.notSupported, lengthPrefixed(Data()))
        }
        return (RDPDriveStatus.success, lengthPrefixed(buffer))
    }

    private func volumeCapacity() -> (total: UInt64, available: UInt64) {
        let values = try? rootURL.resourceValues(forKeys: [.volumeTotalCapacityKey, .volumeAvailableCapacityKey])
        let bytesPerUnit: UInt64 = 512
        let total = UInt64(values?.volumeTotalCapacity ?? 0) / bytesPerUnit
        let available = UInt64(values?.volumeAvailableCapacity ?? 0) / bytesPerUnit
        return (max(total, 1), available)
    }

    // MARK: - DIRECTORY_CONTROL / QUERY_DIRECTORY

    private func queryDirectory(_ fileID: UInt32, _ body: inout ByteCursor) -> (UInt32, Data) {
        guard let infoClass = try? body.readLittleEndianUInt32(),
              let initialQuery = try? body.readUInt8(),
              let pathLength = try? body.readLittleEndianUInt32(),
              let _ = try? body.readData(count: 23),                 // Padding
              let pathData = try? body.readData(count: Int(pathLength)),
              var file = openFiles[fileID], file.isDirectory
        else { return failure() }
        _ = pathData   // wildcard pattern; we return all entries

        if initialQuery != 0 || file.enumeration == nil {
            let children = (try? fileManager.contentsOfDirectory(
                at: file.url, includingPropertiesForKeys: nil, options: []
            )) ?? []
            file.enumeration = children.sorted { $0.lastPathComponent < $1.lastPathComponent }
            file.enumIndex = 0
        }
        guard let entries = file.enumeration, file.enumIndex < entries.count else {
            openFiles[fileID] = file
            return (RDPDriveStatus.noMoreFiles, lengthPrefixed(Data()))
        }

        // One entry per response keeps the encoding simple and avoids NextEntryOffset alignment bugs.
        let url = entries[file.enumIndex]
        file.enumIndex += 1
        openFiles[fileID] = file
        let entry = directoryEntry(for: url, infoClass: infoClass)
        return (RDPDriveStatus.success, lengthPrefixed(entry))
    }

    private func directoryEntry(for url: URL, infoClass: UInt32) -> Data {
        let attributes = try? fileManager.attributesOfItem(atPath: url.path)
        let isDir = (attributes?[.type] as? FileAttributeType) == .typeDirectory
        let size = (attributes?[.size] as? UInt64) ?? 0
        let created = attributes?[.creationDate] as? Date
        let modified = attributes?[.modificationDate] as? Date
        let name = utf16LE(url.lastPathComponent)   // no null terminator in directory entries
        let attrs = fileAttributes(url, isDirectory: isDir)

        var data = Data()
        data.appendLittleEndianUInt32(0)                           // NextEntryOffset (single entry)
        data.appendLittleEndianUInt32(0)                           // FileIndex
        if infoClass == RDPDriveFsInformationClass.fileNamesInformation {
            data.appendLittleEndianUInt32(UInt32(name.count))     // FileNameLength
            data.append(name)
            return data
        }
        data.appendLittleEndianUInt64(fileTime(created))
        data.appendLittleEndianUInt64(fileTime(modified))
        data.appendLittleEndianUInt64(fileTime(modified))
        data.appendLittleEndianUInt64(fileTime(modified))
        data.appendLittleEndianUInt64(size)                       // EndOfFile
        data.appendLittleEndianUInt64(size)                       // AllocationSize
        data.appendLittleEndianUInt32(attrs)
        data.appendLittleEndianUInt32(UInt32(name.count))         // FileNameLength
        if infoClass == RDPDriveFsInformationClass.fileFullDirectoryInformation
            || infoClass == RDPDriveFsInformationClass.fileBothDirectoryInformation {
            data.appendLittleEndianUInt32(0)                      // EaSize
        }
        if infoClass == RDPDriveFsInformationClass.fileBothDirectoryInformation {
            data.appendUInt8(0)                                   // ShortNameLength
            data.appendUInt8(0)                                   // Reserved
            data.append(Data(count: 24))                          // ShortName[12] UTF-16
        }
        data.append(name)
        return data
    }

    // MARK: - Helpers

    private func allocateFileID() -> UInt32 {
        let id = nextFileID
        nextFileID = nextFileID == UInt32.max ? 1 : nextFileID + 1
        return id
    }

    private func existsDirectory(_ url: URL) -> Bool {
        var isDir: ObjCBool = false
        return fileManager.fileExists(atPath: url.path, isDirectory: &isDir) && isDir.boolValue
    }

    private func makeItem(at url: URL, directory: Bool) -> Bool {
        if directory {
            return (try? fileManager.createDirectory(at: url, withIntermediateDirectories: false)) != nil
        }
        return fileManager.createFile(atPath: url.path, contents: Data())
    }

    private func fileAttributes(_ url: URL, isDirectory: Bool) -> UInt32 {
        var attrs: UInt32 = 0
        if isDirectory { attrs |= RDPDriveFileAttribute.directory }
        if url.lastPathComponent.hasPrefix(".") { attrs |= RDPDriveFileAttribute.hidden }
        if fileManager.isWritableFile(atPath: url.path) == false { attrs |= RDPDriveFileAttribute.readonly }
        if isDirectory == false, attrs == 0 { attrs = RDPDriveFileAttribute.archive }
        return attrs
    }

    private func failure() -> (UInt32, Data) { (RDPDriveStatus.unsuccessful, Data()) }

    private func lengthPrefixed(_ buffer: Data) -> Data {
        var data = Data()
        data.appendLittleEndianUInt32(UInt32(buffer.count))
        data.append(buffer)
        return data
    }

    private func fileTime(_ date: Date?) -> UInt64 {
        guard let date else { return 0 }
        let secondsSince1601 = date.timeIntervalSince1970 + 11_644_473_600
        guard secondsSince1601 > 0 else { return 0 }
        return UInt64(secondsSince1601 * 10_000_000)
    }

    private func utf16LE(_ value: String) -> Data {
        var data = Data()
        for unit in value.utf16 { data.appendLittleEndianUInt16(unit) }
        return data
    }

    private func decodeUTF16(_ data: Data) -> String {
        var cursor = ByteCursor(data)
        var units: [UInt16] = []
        while let unit = try? cursor.readLittleEndianUInt16(), unit != 0 { units.append(unit) }
        return String(decoding: units, as: UTF16.self)
    }
}
