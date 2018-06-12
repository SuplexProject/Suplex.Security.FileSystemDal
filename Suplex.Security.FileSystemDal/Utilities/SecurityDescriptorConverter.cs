using System;
using System.Collections.Generic;
using Suplex.Security.AclModel;

using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using YamlDotNet.Serialization;

namespace Suplex.Security.AclModel.DataAccess.Utilities
{
    public class SecurityDescriptorConverter : IYamlTypeConverter
    {
        public bool Accepts(Type type)
        {
            return typeof( ISecurityDescriptor ).IsAssignableFrom( type );
        }

        public object ReadYaml(IParser parser, Type type)
        {
            ISecurityDescriptor sd = null;

            if( type == typeof( ISecurityDescriptor ) && parser.Current.GetType() == typeof( MappingStart ) )
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

                sd = new SecurityDescriptor();
                foreach( string prop in props.Keys )
                {
                    if( prop.Equals( nameof( sd.DaclAllowInherit ) ) )
                        sd.DaclAllowInherit = bool.Parse( props[prop] );
                    //else if( prop.Equals( RightFields.Right ) )
                    //    ace.SetRight( props[prop] );
                    else if( prop.Equals( nameof( sd.SaclAllowInherit ) ) )
                        sd.SaclAllowInherit = bool.Parse( props[prop] );
                    else if( prop.Equals( nameof( sd.SaclAuditTypeFilter ) ) )
                        sd.SaclAuditTypeFilter = (AuditType)Enum.Parse( typeof( AuditType ), props[prop] );
                }
            }

            return sd;
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

                if( ace.TrusteeUId.HasValue )
                {
                    emitter.Emit( new Scalar( null, nameof( ace.TrusteeUId ) ) );
                    emitter.Emit( new Scalar( null, ace.TrusteeUId.ToString() ) );
                }
            }

            emitter.Emit( new MappingEnd() );
        }
    }
}