package eu.olympus.model;

import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.multisign.MSsignature;
import eu.olympus.util.psmultisign.PSsignature;
import org.apache.commons.codec.binary.Base64;
import java.util.HashMap;
import java.util.Map;

public class PSCredential {

    private final long epoch;
    private final Map<String, Attribute> attributes;
    private final MSsignature signature;


    public PSCredential(long epoch, Map<String, Attribute> attributes, MSsignature signature) {
        this.epoch = epoch;
        this.attributes = new HashMap<>(attributes);
        this.signature=signature;
    }
    public PSCredential(String psCredential) throws InvalidProtocolBufferException {
        PabcSerializer.PScredential protoCred=PabcSerializer.PScredential.parseFrom(Base64.decodeBase64(psCredential));
        this.epoch=protoCred.getEpoch();
        this.signature=new PSsignature(protoCred.getSignature());
        this.attributes=new HashMap<>();
        Map<String,PabcSerializer.Attribute> protoAttr=protoCred.getRevealedAttributesMap();
        for (String attr:protoAttr.keySet()){
            this.attributes.put(attr,new Attribute(protoAttr.get(attr)));
        }
    }

    public long getEpoch() {
        return epoch;
    }

    public Map<String, Attribute> getAttributes() {
        return attributes;
    }

    public Attribute getElement(String key) {
        return this.attributes.get(key);
    }

    public MSsignature getSignature() {
        return this.signature;
    }

    public String getEncoded() {
        return Base64.encodeBase64String(toProto().toByteArray());
    }

    private PabcSerializer.PScredential toProto(){
        Map<String,PabcSerializer.Attribute> protoAttributes=new HashMap<>();
        for(String attrName:attributes.keySet())
            protoAttributes.put(attrName,attributes.get(attrName).toProto());
        return PabcSerializer.PScredential.newBuilder()
                .setEpoch(epoch)
                .setSignature(((PSsignature)signature).toProto())
                .putAllRevealedAttributes(protoAttributes)
                .build();
    }
}
