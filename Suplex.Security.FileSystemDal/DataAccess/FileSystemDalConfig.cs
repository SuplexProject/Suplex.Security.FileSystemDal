namespace Suplex.Security.DataAccess
{
    public class FileSystemDalConfig
    {
        public string FilePath { get; set; }
        public bool AutomaticallyPersistChanges { get; set; }
        public bool SerializeAsJson { get; internal set; }
    }
}