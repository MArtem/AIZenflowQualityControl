import Foundation

actor SafeStore {
    private var value = 0

    func increment() {
        value += 1
    }
}
