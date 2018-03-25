using System;
using System.Collections.Generic;

using Suplex.Security.AclModel.DataAccess.Utilities;
using Suplex.Utilities.Serialization;

using YamlDotNet.Serialization;


namespace Suplex.Security.AclModel.DataAccess
{
    public class FileStore : SuplexStore
    {
        MemoryDal _dal = null;
        [YamlIgnore]
        public MemoryDal Dal
        {
            get
            {
                if( _dal == null )
                    _dal = new MemoryDal( this );

                return _dal;
            }
        }

        [YamlIgnore]
        public string CurrentPath { get; internal set; }



        public string ToYaml(bool serializeAsJson = false)
        {
            FileStore clone = new FileStore
            {
                Users = Users,
                Groups = Groups,
                GroupMembership = GroupMembership
            };
            SecureObjects.ShallowCloneTo( clone.SecureObjects );

            return YamlHelpers.Serialize( clone,
                serializeAsJson: serializeAsJson, formatJson: serializeAsJson, converter: new YamlAceConveter() );
        }

        public void ToYamlFile(string path = null, bool serializeAsJson = false)
        {
            if( string.IsNullOrWhiteSpace( path ) && !string.IsNullOrWhiteSpace( CurrentPath ) )
                path = CurrentPath;

            if( string.IsNullOrWhiteSpace( path ) )
                throw new ArgumentException( "path or CurrentPath must not be null." );

            FileStore clone = new FileStore
            {
                Users = Users,
                Groups = Groups,
                GroupMembership = GroupMembership
            };
            SecureObjects.ShallowCloneTo( clone.SecureObjects );

            YamlHelpers.SerializeFile( path, clone,
                serializeAsJson: serializeAsJson, formatJson: serializeAsJson, converter: new YamlAceConveter() );

            CurrentPath = path;
        }

        public static FileStore FromYaml(string yaml)
        {
            return YamlHelpers.Deserialize<FileStore>( yaml, converter: new YamlAceConveter() );
        }

        public static FileStore FromYamlFile(string path)
        {
            FileStore store = YamlHelpers.DeserializeFile<FileStore>( path, converter: new YamlAceConveter() );
            store.CurrentPath = path;
            return store;
        }

        void ShallowCloneTo(List<SecureObject> source, List<SecureObject> destination)
        {
            foreach( SecureObject item in source )
            {
                SecureObject clone = item.Clone();
                destination.Add( clone );
                if( item.Children != null && item.Children.Count > 0 )
                    ShallowCloneTo( item.Children, clone.Children );
            }
        }
    }
}