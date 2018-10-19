using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

using Suplex.Security.AclModel;
using Suplex.Security.DataAccess;
using Suplex.Security.Principal;
using Suplex.Utilities.Serialization;

public class FileSystemDal : MemoryDal, ISuplexDalHost
{
    public FileSystemDal()
    {
        Store = new SuplexStore();
    }

    public ISuplexDal Dal => this;

    public void Configure(object config)
    {
        string yaml = YamlHelpers.Serialize( config );
        FileSystemDalConfig fileSystemDalConfig = YamlHelpers.Deserialize<FileSystemDalConfig>( yaml );
        Configure( fileSystemDalConfig );
    }
    public void Configure(FileSystemDalConfig fileSystemDalConfig)
    {
        FromYamlFile( fileSystemDalConfig.FilePath );
        AutomaticallyPersistChanges = fileSystemDalConfig.AutomaticallyPersistChanges;
        SerializeAsJson = fileSystemDalConfig.SerializeAsJson;
    }


    public virtual string CurrentPath { get; set; }
    public virtual bool AutomaticallyPersistChanges { get; set; }
    public bool SerializeAsJson { get; set; }
    protected virtual bool SaveChanges { get { return !string.IsNullOrWhiteSpace( CurrentPath ) && AutomaticallyPersistChanges; } }


    #region overrides
    override public User UpsertUser(User user)
    {
        User x = base.UpsertUser( user );
        if( SaveChanges ) LockedSaveChanges();
        return x;
    }

    override public void DeleteUser(Guid userUId)
    {
        base.DeleteUser( userUId );
        if( SaveChanges ) LockedSaveChanges();
    }

    override public Group UpsertGroup(Group group)
    {
        Group x = base.UpsertGroup( group );
        if( SaveChanges ) LockedSaveChanges();
        return x;
    }

    override public void DeleteGroup(Guid groupUId)
    {
        base.DeleteGroup( groupUId );
        if( SaveChanges ) LockedSaveChanges();
    }

    override public GroupMembershipItem UpsertGroupMembership(GroupMembershipItem groupMembershipItem)
    {
        GroupMembershipItem x = base.UpsertGroupMembership( groupMembershipItem );
        if( SaveChanges ) LockedSaveChanges();
        return x;
    }

    override public List<GroupMembershipItem> UpsertGroupMembership(List<GroupMembershipItem> groupMembershipItems)
    {
        List<GroupMembershipItem> x = base.UpsertGroupMembership( groupMembershipItems );
        if( SaveChanges ) LockedSaveChanges();
        return x;
    }

    override public void DeleteGroupMembership(GroupMembershipItem groupMembershipItem)
    {
        base.DeleteGroupMembership( groupMembershipItem );
        if( SaveChanges ) LockedSaveChanges();
    }

    override public ISecureObject UpsertSecureObject(ISecureObject secureObject)
    {
        ISecureObject x = base.UpsertSecureObject( secureObject );
        if( SaveChanges ) LockedSaveChanges();
        return x;
    }

    override public void UpdateSecureObjectParentUId(ISecureObject secureObject, Guid? newParentUId)
    {
        base.UpdateSecureObjectParentUId( secureObject, newParentUId );
        if( SaveChanges ) LockedSaveChanges();
    }

    override public void DeleteSecureObject(Guid secureObjectUId)
    {
        base.DeleteSecureObject( secureObjectUId );
        if( SaveChanges ) LockedSaveChanges();
    }


    protected virtual void LockedSaveChanges()
    {
        //return;

        AutoResetEvent autoResetEvent = new AutoResetEvent( false );

        while( true )
        {
            try
            {
                ToYamlFile( serializeAsJson: SerializeAsJson );
                break;
            }
            catch( IOException )
            {
                FileSystemWatcher fileSystemWatcher =
                    new FileSystemWatcher( Path.GetDirectoryName( CurrentPath ) )
                    {
                        EnableRaisingEvents = true
                    };

                fileSystemWatcher.Changed += (o, e) =>
                {
                    if( Path.GetFullPath( e.FullPath ) == Path.GetFullPath( CurrentPath ) )
                        autoResetEvent.Set();
                };

                autoResetEvent.WaitOne();
            }
        }
    }
    #endregion


    #region To/From Yaml
    public string ToYaml(bool serializeAsJson = false)
    {
        SuplexStore clone = new SuplexStore
        {
            Users = Store.Users,
            Groups = Store.Groups,
            GroupMembership = Store.GroupMembership
        };
        Store.SecureObjects.ShallowCloneTo( clone.SecureObjects );

        return YamlHelpers.Serialize( clone,
            serializeAsJson: serializeAsJson, formatJson: serializeAsJson, emitDefaultValues: true, converter: new YamlAceConverter() );
    }

    public void ToYamlFile(string path = null, bool serializeAsJson = false)
    {
        if( string.IsNullOrWhiteSpace( path ) && !string.IsNullOrWhiteSpace( CurrentPath ) )
            path = CurrentPath;

        if( string.IsNullOrWhiteSpace( path ) )
            throw new ArgumentException( "path or CurrentPath must not be null." );

        SuplexStore clone = new SuplexStore
        {
            Users = Store.Users,
            Groups = Store.Groups,
            GroupMembership = Store.GroupMembership
        };
        Store.SecureObjects.ShallowCloneTo( clone.SecureObjects );

        YamlHelpers.SerializeFile( path, clone,
            serializeAsJson: serializeAsJson, formatJson: serializeAsJson, emitDefaultValues: true, converter: new YamlAceConverter() );

        CurrentPath = path;
    }

    public void FromYaml(string yaml)
    {
        Store = YamlHelpers.Deserialize<SuplexStore>( yaml, converter: new YamlAceConverter() );
        CurrentPath = null;
    }

    public void FromYamlFile(string path)
    {
        Store = YamlHelpers.DeserializeFile<SuplexStore>( path, converter: new YamlAceConverter() );
        CurrentPath = path;
    }

    public static FileSystemDal LoadFromYaml(string yaml)
    {
        FileSystemDal fileSystemDal = new FileSystemDal
        {
            Store = YamlHelpers.Deserialize<SuplexStore>( yaml, converter: new YamlAceConverter() ),
            CurrentPath = null
        };
        return fileSystemDal;
    }

    public static FileSystemDal LoadFromYamlFile(string path)
    {
        FileSystemDal fileSystemDal = new FileSystemDal
        {
            Store = YamlHelpers.DeserializeFile<SuplexStore>( path, converter: new YamlAceConverter() ),
            CurrentPath = path
        };
        return fileSystemDal;
    }

    void ShallowCloneTo(IList<SecureObject> source, IList<SecureObject> destination)
    {
        foreach( SecureObject item in source )
        {
            SecureObject clone = item.Clone();
            destination.Add( clone );
            if( item.Children != null && item.Children.Count > 0 )
                ShallowCloneTo( item.Children, clone.Children );
        }
    }
    #endregion
}