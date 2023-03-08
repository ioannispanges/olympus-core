package eu.olympus.model;

import eu.olympus.protos.serializer.PabcSerializer;

public enum AttributeType {
    STRING {
        @Override
        public String toString() {
            return "String";
        }
    },
    INTEGER {
        @Override
        public String toString() {
            return "Integer";
        }
     },
    BOOLEAN {
         @Override
         public String toString() {
             return "Boolean";
         }
      },
    DATE{
        @Override
        public String toString() {
            return "Date";
        }
    }; 
	
    public static class ProtobufTypeTransformation {
        public static AttributeType fromProto(PabcSerializer.AttributeType type){
            switch(type.name()){
                case "STRING": return  AttributeType.STRING;
                case "INTEGER": return  AttributeType.INTEGER;
                case "DATE": return  AttributeType.DATE;
                case "BOOLEAN": return  AttributeType.BOOLEAN;
                default:
                    return null;
            }
        }

        public static PabcSerializer.AttributeType  toProto(AttributeType type){
            switch(type.name()){
                case "STRING": return  PabcSerializer.AttributeType.STRING;
                case "INTEGER": return  PabcSerializer.AttributeType.INTEGER;
                case "DATE": return  PabcSerializer.AttributeType.DATE;
                case "BOOLEAN": return  PabcSerializer.AttributeType.BOOLEAN;
                default:
                    return null;
            }
        }
    }
}
