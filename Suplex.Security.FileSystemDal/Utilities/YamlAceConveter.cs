using System;
using System.Collections.Generic;
using Suplex.Security.AclModel;

using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using YamlDotNet.Serialization;

namespace Suplex.Security.AclModel.DataAccess.Utilities
{
    public class YamlAceConveter : IYamlTypeConverter
    {
        public bool Accepts(Type type)
        {
            return typeof( IAccessControlEntry ).IsAssignableFrom( type );
        }

        public object ReadYaml(IParser parser, Type type)
        {
            IAccessControlEntry ace = null;

            if( type == typeof( IAccessControlEntry ) && parser.Current.GetType() == typeof( MappingStart ) )
            {
                parser.MoveNext(); // skip the sequence start

                Dictionary<string, string> props = new Dictionary<string, string>();
                while( parser.Current.GetType() != typeof( MappingEnd ) )
                {
                    string prop = ((Scalar)parser.Current).Value;
                    parser.MoveNext();
                    string value = ((Scalar)parser.Current).Value;
                    parser.MoveNext();

                    props[prop] = value;
                }
                parser.MoveNext();

                if( props.ContainsKey( RightFields.RightType ) )
                    ace = AccessControlEntryUtilities.MakeAceFromRightType( props[RightFields.RightType], props );
            }

            return ace;
        }

        public void WriteYaml(IEmitter emitter, object value, Type type)
        {
            emitter.Emit( new MappingStart( null, null, false, MappingStyle.Block ) );

            if( value is IAccessControlEntry ace )
            {

                if( ace.UId.HasValue )
                {
                    emitter.Emit( new Scalar( null, nameof( ace.UId ) ) );
                    emitter.Emit( new Scalar( null, ace.UId.ToString() ) );
                }

                emitter.Emit( new Scalar( null, RightFields.RightType ) );
                emitter.Emit( new Scalar( null, ace.RightData.RightType.AssemblyQualifiedName ) );
                emitter.Emit( new Scalar( null, RightFields.Right ) );
                emitter.Emit( new Scalar( null, ace.RightData.Name ) );

                emitter.Emit( new Scalar( null, nameof( ace.Allowed ) ) );
                emitter.Emit( new Scalar( null, ace.Allowed.ToString() ) );

                if( ace is IAccessControlEntryAudit auditace )
                {
                    emitter.Emit( new Scalar( null, nameof( auditace.Denied ) ) );
                    emitter.Emit( new Scalar( null, auditace.Denied.ToString() ) );
                }

                emitter.Emit( new Scalar( null, nameof( ace.Inheritable ) ) );
                emitter.Emit( new Scalar( null, ace.Inheritable.ToString() ) );

                if( ace.InheritedFrom.HasValue )
                {
                    emitter.Emit( new Scalar( null, nameof( ace.InheritedFrom ) ) );
                    emitter.Emit( new Scalar( null, ace.InheritedFrom.ToString() ) );
                }

                if( ace.SecurityPrincipalUId.HasValue )
                {
                    emitter.Emit( new Scalar( null, nameof( ace.SecurityPrincipalUId ) ) );
                    emitter.Emit( new Scalar( null, ace.SecurityPrincipalUId.ToString() ) );
                }
            }

            emitter.Emit( new MappingEnd() );
        }
    }
}