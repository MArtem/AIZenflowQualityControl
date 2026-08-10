import PackagePlugin

@main
struct EngineBuildProvenancePlugin: BuildToolPlugin {
    func createBuildCommands(context: PluginContext, target: Target) throws -> [Command] {
        guard target.name == "QualityCLI" else { return [] }
        let provenanceInputs = context.package.targets
            .compactMap { $0 as? SourceModuleTarget }
            .filter { $0.name == "QualityCLI" || $0.name == "QualityCore" }
            .flatMap { $0.sourceFiles.map(\.url) }
        let inputFiles = [context.package.directoryURL.appending(path: "Package.swift")] + provenanceInputs
        return [
            .buildCommand(
                displayName: "Generate engine build provenance",
                executable: try context.tool(named: "EngineBuildProvenanceGenerator").url,
                arguments: [
                    "--package-root", context.package.directoryURL.path,
                    "--output", context.pluginWorkDirectoryURL.appending(path: "EngineBuildProvenance.swift").path
                ] + inputFiles.flatMap { ["--input", $0.path] },
                inputFiles: inputFiles,
                outputFiles: [context.pluginWorkDirectoryURL.appending(path: "EngineBuildProvenance.swift")]
            )
        ]
    }
}
