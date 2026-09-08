struct Failing {
    func forceCast(_ value: Any) -> String {
        value as! String
    }
}
