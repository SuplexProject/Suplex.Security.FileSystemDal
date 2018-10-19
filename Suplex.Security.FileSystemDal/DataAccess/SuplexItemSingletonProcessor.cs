using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using Suplex.Security.AclModel;
using Suplex.Security.DataAccess;
using Suplex.Security.Principal;

public sealed class SuplexItemSingletonProcessor
{
    private static readonly Lazy<SuplexItemSingletonProcessor> lazy =
        new Lazy<SuplexItemSingletonProcessor>( () => new SuplexItemSingletonProcessor() );

    public static SuplexItemSingletonProcessor Instance { get { return lazy.Value; } }

    private SuplexItemSingletonProcessor()
    {
        Queue = new ConcurrentQueue<SuplexUpdateItem>();
        Exceptions = new ConcurrentQueue<Exception>();
        Fatal = new ConcurrentQueue<Exception>();
    }

    public ConcurrentQueue<SuplexUpdateItem> Queue { get; }
    public ConcurrentQueue<Exception> Exceptions { get; }
    public ConcurrentQueue<Exception> Fatal { get; }

    FileSystemDal _dal = null;

    public void StartQueueWatcher(FileSystemDal suplexDalInstance)
    {
        if( _dal == null )
        {
            _dal = suplexDalInstance;

            Thread thread = new Thread( () => Instance.DrainQueue() )
            {
                IsBackground = true,
                Name = "SuplexItemThread"
            };
            thread.Start();
        }
    }

    public void WaitForReadyToExit()
    {
        //Thread thread = new Thread( () =>
        //{
        //    while( Instance.Queue.Count > 0 )
        //        Thread.Sleep( 500 );
        //    ReadyToExit = true;
        //} )
        //{
        //    IsBackground = true,
        //    Name = "WaitThread"
        //};
        //thread.Start();
        System.Timers.Timer SuplexPoller = new System.Timers.Timer( 500 )
        {
            Enabled = true
        };
        SuplexPoller.Elapsed += (s, e) =>
        {
            if( Instance.Queue.Count > 0 )
                DrainQueue();
            SuplexPoller.Enabled = false;
        };
    }


    bool _allowExit = false;
    public bool ReadyToExit = false;
    void DrainQueue()
    {
        while( true )
        {
            if( Instance.Queue.Count == 0 )
            {
                Thread.Sleep( 500 ); //no pending actions available, pause
                //if( _allowExit )
                //    ReadyToExit = true;
                continue;
            }
            _allowExit = true;

            SuplexUpdateItem item = null;
            while( Instance.Queue.TryDequeue( out item ) )
            {
                FileSystemDal fsd = _dal;
                if( File.Exists( _dal.CurrentPath ) )
                    fsd = FileSystemDal.LoadFromYamlFile( _dal.CurrentPath );

                if( item.IsSecureObject )
                    fsd.UpsertSecureObject( item.Item as ISecureObject );
                else if( item.IsUser )
                    fsd.UpsertUser( item.Item as User );
                else if( item.IsGroup )
                    fsd.UpsertGroup( item.Item as Group );
                else if( item.IsGroupMembership )
                    fsd.UpsertGroupMembership( item.Item as GroupMembershipItem );
                else
                    throw new Exception( $"Unknown type {item.GetType()}" );

                fsd.ToYamlFile();
            }
        }
    }
}

public class SuplexUpdateItem
{
    public object Item { get; set; }

    public bool IsSecureObject { get { return Item is ISecureObject; } }
    public bool IsUser { get { return Item is User; } }
    public bool IsGroup { get { return Item is Group; } }
    public bool IsGroupMembership { get { return Item is GroupMembershipItem; } }
}