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
            ISecurityDescriptor sd = new SecurityDescriptor
            {
                Dacl = new DiscretionaryAcl(),
                Sacl = new SystemAcl()
            };

            if( type == typeof( ISecurityDescriptor ) && parser.Current.GetType() == typeof( MappingStart ) )
            {
                parser.MoveNext(); // skip the sequence start

                Dictionary<string, string> props = new Dictionary<string, string>();
                while( parser.Current.GetType() != typeof( SequenceStart ) )
                {
                    string prop = ((Scalar)parser.Current).Value;
                    parser.MoveNext();

                    if( parser.Current is Scalar )
                    {
                        string value = ((Scalar)parser.Current).Value;
                        parser.MoveNext();

                        props[prop] = value;
                    }
                }
                parser.MoveNext();

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

                YamlAceConverter yac = new YamlAceConverter();
                while( parser.Current.GetType() != typeof( MappingEnd ) )
                    yac.ReadYaml( parser, typeof( IAccessControlEntry ) );
                parser.MoveNext();
            }

            return sd;
        }

        public void WriteYaml(IEmitter emitter, object value, Type type)
        {
            emitter.Emit( new MappingStart( null, null, false, MappingStyle.Block ) );

            if( value is ISecurityDescriptor sd )
            {
                emitter.Emit( new Scalar( null, nameof( sd.DaclAllowInherit ) ) );
                emitter.Emit( new Scalar( null, sd.DaclAllowInherit.ToString() ) );

                emitter.Emit( new Scalar( null, nameof( sd.SaclAllowInherit ) ) );
                emitter.Emit( new Scalar( null, sd.SaclAllowInherit.ToString() ) );

                emitter.Emit( new Scalar( null, nameof( sd.SaclAuditTypeFilter ) ) );
                emitter.Emit( new Scalar( null, sd.SaclAuditTypeFilter.ToString() ) );
            }

            emitter.Emit( new MappingEnd() );
        }
    }
}