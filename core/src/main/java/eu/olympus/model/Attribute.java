package eu.olympus.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.protobuf.ByteString;
import eu.olympus.protos.serializer.PabcSerializer;

import java.util.Date;


import org.apache.commons.codec.Charsets;

public class Attribute {

	private Object attr;
	private AttributeType type;

    public Attribute() {
    }

    public Attribute(@JsonProperty("attr")Object attr, @JsonProperty("type")AttributeType type){
        if(type==AttributeType.DATE && attr instanceof Long){
            //Needed to avoid serialization problem when Jackson is being used.
            this.attr=new Date((Long)attr);
            this.type=type;
        }else if(type==AttributeType.DATE && attr instanceof Integer) {
            //Needed to avoid serialization problem when Jackson is being used.
            this.attr = new Date((Integer) attr);
            this.type = type;
        }
        else{
            this.attr=attr;
            this.type=type;
        }
    }

    //TODO Using Long for "INTEGER" representation would give a big enough range for any reasonable use case (integer might be enough though)
    // (problem with object mapper always taking integer when deserializing object)
    public Attribute(Integer attr){
        this.attr=attr;
        this.type=AttributeType.INTEGER;
    }

    public Attribute(String attr){
        this.attr=attr;
        this.type=AttributeType.STRING;
    }

    public Attribute(Date attr){
        this.attr=attr;
        this.type=AttributeType.DATE;
    }

    public Attribute(boolean attr) {
    	this.attr = attr;
    	this.type = AttributeType.BOOLEAN;
    }
    
    public Attribute(PabcSerializer.Attribute attr){
        this.type= AttributeType.ProtobufTypeTransformation.fromProto( attr.getType());
        switch (type){
            case STRING:
                this.attr=new String(attr.getObj().toByteArray());
                break;
            case INTEGER:
                this.attr=IntFromByteArray(attr.getObj().toByteArray());
                break;
            case DATE:
                this.attr=new Date(bytesToLong(attr.getObj().toByteArray()));
                break;
            case BOOLEAN:
                this.attr= bytesToBool(attr.getObj().toByteArray());
                break;
            default:
                this.attr=null;
        }
    }

    private Object bytesToBool(byte[] byteArray) {
		if(byteArray[0] ==0) {
			return new Boolean(false);
		} else {
			return new Boolean(true);
		}
	}

	public Object getAttr() {
        return attr;
    }

    public AttributeType getType() {
        return type;
    }

    @Override
    public String toString(){
        return attr.toString();
    }

    public PabcSerializer.Attribute toProto(){
        byte[] objBytes=null;
        switch (type){
            case STRING:
                objBytes=((String) attr).getBytes(Charsets.UTF_8);
                break;
            case INTEGER:
                objBytes=IntToByteArray((Integer) attr);
                break;
            case DATE:
                objBytes=longToBytes(((Date) attr).getTime());
                break;
            case BOOLEAN:
                objBytes=boolToBytes((Boolean) attr);
                break;
            default:
                break;
        }
        return  PabcSerializer.Attribute.newBuilder()
                .setObj(ByteString.copyFrom(objBytes))
                .setType(AttributeType.ProtobufTypeTransformation.toProto(type))
                .build();
    }

    private byte[] boolToBytes(Boolean attr2) {
    	if(attr2) {
    		return new byte[] {1};
    	} else {
    		return new byte[] {0};
    	}
	}

	private static byte[] IntToByteArray(int value) {
        return new byte[] {
                (byte)(value >> 24),
                (byte)(value >> 16),
                (byte)(value >> 8),
                (byte)value };
    }

    private static int IntFromByteArray(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8 ) |
                ((bytes[3] & 0xFF) << 0 );
    }

    private static byte[] longToBytes(long l) {
        byte[] result = new byte[8];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte)(l & 0xFF);
            l >>= 8;
        }
        return result;
    }

    private static long bytesToLong(byte[] b) {
        long result = 0;
        for (int i = 0; i < 8; i++) {
            result <<= 8;
            result |= (b[i] & 0xFF);
        }
        return result;
    }

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((attr == null) ? 0 : attr.hashCode());
		result = prime * result + ((type == null) ? 0 : type.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Attribute other = (Attribute) obj;
		if (attr == null) {
			if (other.attr != null)
				return false;
		} else if (!attr.equals(other.attr))
			return false;
		if (type != other.type)
			return false;
		return true;
	}
    
    
}
