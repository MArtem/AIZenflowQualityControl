import PackagePlugin

@main
struct EngineBuildProvenancePlugin: BuildToolPlugin {
    func createBuildCommands(context: PluginContext, target: Target) throws -> [Command] {
        guard target.name == "QualityCLI" else { return [] }
        return [
            .buildCommand(
                displayName: "Generate engine build provenance",
                executable: try context.tool(named: "EngineBuildProvenanceGenerator").url,
                arguments: [
                    "--package-root", context.package.directoryURL.path,
                    "--output", context.pluginWorkDirectoryURL.appending(path: "EngineBuildProvenance.swift").path
                ],
                inputFiles: [context.package.directoryURL.appending(path: "Package.swift")],
                outputFiles: [context.pluginWorkDirectoryURL.appending(path: "EngineBuildProvenance.swift")]
            )
        ]
    }
}
