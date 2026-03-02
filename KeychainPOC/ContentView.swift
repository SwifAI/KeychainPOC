import SwiftUI

struct ContentView: View {

    @State private var logs: [LogEntry] = []
    @State private var isGenerating = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {

                // Action buttons
                VStack(spacing: 12) {
                    Button(action: generateKeys) {
                        Label("Generate Key Pair", systemImage: "key.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isGenerating)

                    Button(action: checkKeys) {
                        Label("Check Keys Exist", systemImage: "magnifyingglass")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)

                    Button(action: testEncryptDecrypt) {
                        Label("Test Encrypt / Decrypt", systemImage: "lock.shield")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)

                    Button(role: .destructive, action: deleteKeys) {
                        Label("Delete Keys", systemImage: "trash")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                }
                .padding(.horizontal)

                Divider()

                // Log output
                ScrollViewReader { proxy in
                    List(logs) { entry in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: entry.icon)
                                .foregroundColor(entry.color)
                                .frame(width: 20)
                            Text(entry.message)
                                .font(.system(.caption, design: .monospaced))
                        }
                        .id(entry.id)
                    }
                    .listStyle(.plain)
                    .onChange(of: logs.count) {
                        if let last = logs.last {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }
            .navigationTitle("Keychain POC")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Clear") { logs.removeAll() }
                }
            }
            .onAppear {
                log(.info, "App launched — tap 'Check Keys Exist' to see if keys survived restart")
                checkKeys()
            }
        }
    }

    // MARK: - Actions

    private func generateKeys() {
        isGenerating = true
        log(.info, "Generating RSA 2048-bit key pair...")

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try KeychainManager.generateKeyPair()
                DispatchQueue.main.async {
                    log(.success, "Key pair generated and saved to Keychain")
                    checkKeys()
                    isGenerating = false
                }
            } catch {
                DispatchQueue.main.async {
                    log(.error, "Generation failed: \(error.localizedDescription)")
                    isGenerating = false
                }
            }
        }
    }

    private func checkKeys() {
        log(.info, "--- Checking Keychain ---")

        let privateCheck = KeychainManager.keyExists(KeychainManager.privateKeyTag)
        let publicCheck  = KeychainManager.keyExists(KeychainManager.publicKeyTag)

        if privateCheck.exists {
            log(.success, "Private key FOUND in Keychain")
        } else {
            log(.error, "Private key NOT FOUND (OSStatus: \(privateCheck.status))")
        }

        if publicCheck.exists {
            log(.success, "Public key FOUND in Keychain")
        } else {
            log(.error, "Public key NOT FOUND (OSStatus: \(publicCheck.status))")
        }
    }

    private func testEncryptDecrypt() {
        log(.info, "Testing encrypt/decrypt...")
        do {
            let result = try KeychainManager.testEncryptDecrypt()
            log(.success, "Encrypt/Decrypt OK — decrypted: \"\(result)\"")
        } catch {
            log(.error, "Encrypt/Decrypt FAILED: \(error.localizedDescription)")
        }
    }

    private func deleteKeys() {
        KeychainManager.deleteKeyPair()
        log(.info, "Keys deleted from Keychain")
        checkKeys()
    }

    // MARK: - Logging

    private func log(_ level: LogLevel, _ message: String) {
        logs.append(LogEntry(level: level, message: message))
    }
}

// MARK: - Log Model

enum LogLevel {
    case info, success, error
}

struct LogEntry: Identifiable {
    let id = UUID()
    let level: LogLevel
    let message: String

    var icon: String {
        switch level {
        case .info:    return "info.circle"
        case .success: return "checkmark.circle.fill"
        case .error:   return "xmark.circle.fill"
        }
    }

    var color: Color {
        switch level {
        case .info:    return .blue
        case .success: return .green
        case .error:   return .red
        }
    }
}

#Preview {
    ContentView()
}
