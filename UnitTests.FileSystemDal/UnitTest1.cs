using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using NUnit.Framework;

using Suplex.Security.AclModel;
using Suplex.Security.Principal;


namespace UnitTests
{
    class Program
    {
        static void Main(string[] args)
        {
            new UnitTest1().TestMethod1();
        }
    }

    [TestFixture]
    public class UnitTest1
    {
        [Test()]
        public void TestMethod1()
        {
            #region foo
            string foo = @"---
SecureObjects:
- UId: e724bfde-c3d5-424f-a0c6-9497958167f0
  UniqueName: top
  Security:
    DaclAllowInherit: true
    SaclAllowInherit: true
    SaclAuditTypeFilter: SuccessAudit, FailureAudit, Information, Warning, Error
    Dacl:
    - UId: a86dac02-cad3-4a51-9b16-1a3b20dbab37
      RightType: Suplex.Security.AclModel.FileSystemRight, Suplex.Security.Core, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
      Right: FullControl
      Allowed: True
      Inheritable: True
    - UId: 7fb267d9-b4ce-4d56-a052-02aa9e9855d5
      RightType: Suplex.Security.AclModel.FileSystemRight, Suplex.Security.Core, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
      Right: List, Execute
      Allowed: False
      Inheritable: False
    - UId: e7ea73a3-a5ec-4f63-8461-66feec42bb12
      RightType: Suplex.Security.AclModel.UIRight, Suplex.Security.Core, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
      Right: Visible, Operate
      Allowed: True
      Inheritable: True
    Sacl: []
    Results: {}
  Children: []
Users:
- UId: 0bdfe71c-5663-4f7f-be8b-3884373f97be
  Name: x
  IsLocal: true
  IsBuiltIn: true
  IsEnabled: true
- UId: 1bda1876-3281-4a67-b5de-198e9e72ad53
  Name: y
  IsEnabled: true
- UId: 20d134e9-a5ac-46ef-bc7e-fa6dc210e1f9
  Name: z
  IsLocal: true
  IsBuiltIn: true
Groups:
- UId: ff8abe51-116b-4d42-b01a-48f167f71dc7
  Name: gx
  IsEnabled: true
- UId: c05c6deb-6a01-459b-9c87-916003f44429
  Name: gy
  IsEnabled: true
- UId: 66f89524-cc5d-4938-9cd3-b2ce6ec6d75b
  Name: gz
  IsEnabled: true
GroupMembership:
- GroupUId: ff8abe51-116b-4d42-b01a-48f167f71dc7
  MemberUId: 0bdfe71c-5663-4f7f-be8b-3884373f97be
  IsMemberUser: true
- GroupUId: ff8abe51-116b-4d42-b01a-48f167f71dc7
  MemberUId: 1bda1876-3281-4a67-b5de-198e9e72ad53
  IsMemberUser: true
- GroupUId: ff8abe51-116b-4d42-b01a-48f167f71dc7
  MemberUId: c05c6deb-6a01-459b-9c87-916003f44429";
            #endregion

            SecureObject top = new SecureObject() { UniqueName = "top" };
            DiscretionaryAcl topdacl = new DiscretionaryAcl
            {
                new AccessControlEntry<FileSystemRight> { Allowed = true, Right = FileSystemRight.FullControl },
                new AccessControlEntry<FileSystemRight> { Allowed = false, Right = FileSystemRight.Execute | FileSystemRight.List, Inheritable = false },
                new AccessControlEntry<UIRight> { Right= UIRight.Operate | UIRight.Visible }
            };
            top.Security.Dacl = topdacl;
            top.Security.DaclAllowInherit = false;

            SystemAcl topsacl = new SystemAcl
            {
                new AccessControlEntryAudit<FileSystemRight>{ Allowed = true, Denied = true, Right = FileSystemRight.Execute}
            };
            top.Security.Sacl = topsacl;
            top.Security.SaclAllowInherit = false;
            top.Security.SaclAuditTypeFilter = AuditType.FailureAudit | AuditType.Error;

            List<User> users = new List<User>
            {
                new User{ Name = "x", IsBuiltIn = true, IsEnabled = true, IsLocal = true },
                new User{ Name = "y", IsBuiltIn = false, IsEnabled = true, IsLocal = false },
                new User{ Name = "z", IsBuiltIn = true, IsEnabled = false, IsLocal = true }
            };

            List<Group> groups = new List<Group>
            {
                new Group{ Name = "gx", IsEnabled = true, IsLocal = false },
                new Group{ Name = "gy", IsEnabled = true, IsLocal = false },
                new Group{ Name = "gz", IsEnabled = true, IsLocal = false }
            };

            GroupMembershipItem mx = new GroupMembershipItem
            {
                GroupUId = groups[0].UId,
                MemberUId = users[0].UId,
                IsMemberUser = true
            };
            GroupMembershipItem my = new GroupMembershipItem
            {
                GroupUId = groups[0].UId,
                MemberUId = users[1].UId,
                IsMemberUser = true
            };
            GroupMembershipItem mz = new GroupMembershipItem
            {
                GroupUId = groups[0].UId,
                MemberUId = groups[1].UId,
                IsMemberUser = false
            };
            List<GroupMembershipItem> gm = new List<GroupMembershipItem>
            {
                mx, my, mz
            };



            FileSystemDal dal = new FileSystemDal() { };
            dal.Store.SecureObjects = new List<SecureObject>() { top };
            dal.Store.Users = users;
            dal.Store.Groups = groups;
            dal.Store.GroupMembership = gm;

            User ux = dal.Store.Users.GetByName<User>( "x" );


            string x = dal.ToYaml();
            FileSystemDal f = new FileSystemDal();
            f.FromYaml( x );
            f.CurrentPath = "meow.yaml";
            f.AutomaticallyPersistChanges = true;

            bool contains = f.Store.GroupMembership.ContainsItem( mx );

            //bool ok = f.GroupMembership.Resolve( f.Groups, f.Users );

            //FileSystemDal f2 = FileSystemDal.LoadFromYaml( foo );

            User u0 = new User { Name = "gurl" };
            User u1 = new User { Name = "f", UId = u0.UId };

            f.Dal.UpsertUser( u0 );
            f.Dal.UpsertUser( u1 );


            for( int i = 0; i < 50; i++ )
                f.UpsertGroup( new Group { Name = $"{i}_{DateTime.Now.Ticks}" } );

            f.WaitForExit();

            //Parallel.For( 0, 49, i =>
            //{
            //    f.UpsertGroup( new Group { Name = $"{i}_{DateTime.Now.Ticks}" } );
            //} );

            Assert.IsTrue( true );
        }
    }
}