#addin nuget:?package=Cake.Coverlet&version=4.0.1
#tool dotnet:?package=GitVersion.Tool&version=5.12.0
#tool dotnet:?package=dotnet-reportgenerator-globaltool&version=5.2.2

var target = Argument("target", "Default");
var configuration = Argument("configuration", "Release");

const string TEST_COVERAGE_OUTPUT_DIR = "coverage";
var solution = "Relay.sln";
Setup<NostrfiBuildData>(setupContext =>
{
	return new NostrfiBuildData(
		configuration: Argument("configuration", "Release"),
        artifactsDirectory: Directory("./artifacts/"),
        coverageDirectory: Directory("./coverage/"),
        buildDirectories: new List<ConvertableDirectoryPath> {
            Directory("./src/Core/bin/"),
            Directory("./src/Interfaces/bin/"),
            Directory("./src/Models/bin/"),
            Directory("./src/Relay/bin/")
        });
});
Task("Clean")
    .Does<NostrfiBuildData>((data) => {
 
    if (BuildSystem.GitHubActions.IsRunningOnGitHubActions)
    {
      Information("Nothing to clean GitHubActions.");
    }
    else
    {
      foreach(var dir in data.BuildDirs)
      {
          Information($"Cleaning: { dir + Directory(data.Configuration) }");
          CleanDirectory(dir + Directory(data.Configuration));
      }
      Information($"Cleaning: { data.ArtifactsDirectory }");
      CleanDirectory(data.ArtifactsDirectory);
      Information($"Cleaning: { data.CoverageDirectory }");
      CleanDirectory(data.CoverageDirectory);
       /*  CleanDirectories("./coverage");
        CleanDirectories("./artifacts");
        GetFiles(". *//** /* *//** /* *//*.csproj").ToList().ForEach(project => {
                      Information($"Cleaning: { project.ToString() }");
                      DotNetClean(project.ToString());
                    });   */
    }
});

Task("Restore")
    .IsDependentOn("Clean")
    .Description("Restoring the solution dependencies")
    .Does(() => {
    
    Information("Restoring the solution dependencies");
      var settings =  new DotNetRestoreSettings
        {
          Verbosity = DotNetVerbosity.Minimal,
          Sources = new [] { "https://api.nuget.org/v3/index.json" }
        };
   GetFiles("./**/**/*.csproj").ToList().ForEach(project => {
       Information($"Restoring { project.ToString() }");
       DotNetRestore(project.ToString(), settings);
     });
});

Task("Build")
    .IsDependentOn("Restore")
    .Does(() => {
    
     var version = GitVersion(new GitVersionSettings {
            UpdateAssemblyInfo = true
        });
     var buildSettings = new DotNetBuildSettings {
                        Configuration = configuration,
                        MSBuildSettings = new DotNetMSBuildSettings()
                                                      .WithProperty("Version", version.AssemblySemVer)
                                                      .WithProperty("AssemblyVersion", version.AssemblySemVer)
                                                      .WithProperty("FileVersion", version.AssemblySemVer)
                       };
     var projects = GetFiles("./**/**/*.csproj");
     foreach(var project in projects )
     {
         Information($"Building {project.ToString()}");
         DotNetBuild(project.ToString(),buildSettings);
     }
});

Task("Test")
    .IsDependentOn("Build")
    .Does(() => {
       
       var testSettings = new DotNetTestSettings  {
                 Configuration = configuration,
                 NoBuild = true,
       };
        var coverageOutput = Directory(TEST_COVERAGE_OUTPUT_DIR);             
     
       GetFiles("./tests/**/*.csproj").ToList().ForEach(project => {
          Information($"Testing Project : { project.ToString() }");
            
          var codeCoverageOutputName = $"{project.GetFilenameWithoutExtension()}.cobertura.xml";
          var coverletSettings = new CoverletSettings {
              CollectCoverage = true,
               CoverletOutputFormat = CoverletOutputFormat.cobertura,
               CoverletOutputDirectory =  coverageOutput,
               CoverletOutputName =codeCoverageOutputName,
               ArgumentCustomization = args => args.Append($"--logger trx"),
               ExcludeByFile = ["**/*Migrations/*.cs"]
          };
                  
          Information($"Running Tests : { project.ToString()}");
          DotNetTest(project.ToString(), testSettings, coverletSettings );        
        });
     
      Information($"Directory Path : { coverageOutput.ToString()}");
          
      var glob = new GlobPattern($"./{ coverageOutput}/*.cobertura.xml");
         
      Information($"Glob Pattern : { glob.ToString()}");
      var outputDirectory = Directory("./coverage/reports");
     
      var reportSettings = new ReportGeneratorSettings
      {
         ArgumentCustomization = args => args.Append($"-reportTypes:HtmlInline_AzurePipelines_Dark;Cobertura")
      };
         
      ReportGenerator(glob, outputDirectory, reportSettings);
          
         var summaryDirectory = Directory("./coverage/summary");
        var summarySettings = new ReportGeneratorSettings
        {
           ArgumentCustomization = args => args.Append($"-reportTypes:MarkdownSummaryGithub")
        };
        ReportGenerator(glob, summaryDirectory, summarySettings);
});


Task("Default")
       .IsDependentOn("Clean")
       .IsDependentOn("Restore")
       .IsDependentOn("Build")
       .IsDependentOn("Test");
       
RunTarget(target);

public class NostrfiBuildData
{
       public string Configuration { get; }
       public ConvertableDirectoryPath ArtifactsDirectory { get; }
       public ConvertableDirectoryPath CoverageDirectory { get; }
       public DotNetBuildSettings BuildSettings { get; }
       public DotNetPackSettings PackSettings { get; }
       public DotNetTestSettings TestSettings { get; }
       public IReadOnlyList<ConvertableDirectoryPath> BuildDirs { get; }
       
       public NostrfiBuildData(string configuration,
                                       ConvertableDirectoryPath artifactsDirectory,
                                       ConvertableDirectoryPath coverageDirectory,
                                       IReadOnlyList<ConvertableDirectoryPath> buildDirectories)
                               	{
                               		  Configuration = configuration;
                                       ArtifactsDirectory = artifactsDirectory;
                                       CoverageDirectory = coverageDirectory;
                                       BuildDirs = buildDirectories;
                               
                                       BuildSettings = new DotNetBuildSettings {
                                           Configuration = configuration,
                                           NoRestore = true,
                                           ArgumentCustomization = args => args.Append("/property:WarningLevel=0") // Until Warnings are fixed in StyleCop
                                       };
                               
                                       PackSettings = new DotNetPackSettings
                                       {
                                           OutputDirectory = ArtifactsDirectory,
                                           NoBuild = true,
                                           Configuration = Configuration,
                                       };
                               
                                       TestSettings = new DotNetTestSettings
                                       {
                                           NoBuild = true,
                                           Configuration = Configuration
                                       };
                               	}
                               	
}