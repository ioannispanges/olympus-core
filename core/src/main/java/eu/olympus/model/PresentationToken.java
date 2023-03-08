package eu.olympus.model;

import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.multisign.MSzkToken;
import eu.olympus.util.psmultisign.PSzkToken;
import eu.olympus.util.psmultisign.PSzkTokenModified;
import eu.olympus.util.rangeProof.RangePredicateToken;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

public class PresentationToken {

	private final long epoch;
	private final Map<String, Attribute> revealedAttributes;
	private final Map<String, RangePredicateToken> rangeTokens;
	private final MSzkToken zkToken;

	public PresentationToken(long epoch, Map<String, Attribute> revealedAttributes, MSzkToken zkToken, Map<String, RangePredicateToken> rangeTokens) {
		this.epoch = epoch;
		this.revealedAttributes = new HashMap<>(revealedAttributes);
		this.rangeTokens = rangeTokens==null ? new HashMap<>() : new HashMap<>(rangeTokens);
		this.zkToken = zkToken;
	}

	public PresentationToken(String presentationToken) throws InvalidProtocolBufferException {
		PabcSerializer.PresentationToken protoPT = PabcSerializer.PresentationToken
				.parseFrom(Base64.decodeBase64(presentationToken));
		this.epoch = protoPT.getEpoch();
		this.revealedAttributes = new HashMap<>();
		Map<String, PabcSerializer.Attribute> protoAttr = protoPT.getRevealedAttributesMap();
		for (String attrName : protoAttr.keySet()) {
			revealedAttributes.put(attrName, new Attribute(protoAttr.get(attrName)));
		}
		if(protoPT.hasPsZkToken()){
			zkToken = new PSzkToken(protoPT.getPsZkToken());
		}else {
			zkToken = new PSzkTokenModified(protoPT.getPsZkTokenMod());
		}
		this.rangeTokens = new HashMap<>();
		Map<String, PabcSerializer.RangePredToken> protoTokens= protoPT.getRangePredTokensMap();
		for(String attrName: protoTokens.keySet())
			rangeTokens.put(attrName,new RangePredicateToken(protoTokens.get(attrName)));
	}

	public long getEpoch() {
		return epoch;
	}

	public Map<String, Attribute> getRevealedAttributes() {
		return revealedAttributes;
	}

	public MSzkToken getZkToken() {
		return zkToken;
	}

	public String getEncoded() {
		return Base64.encodeBase64String(toProto().toByteArray());
	}

	public Map<String, RangePredicateToken> getRangeTokens() {
		return rangeTokens;
	}

	private PabcSerializer.PresentationToken toProto() {
		Map<String, PabcSerializer.Attribute> protoAttributes = new HashMap<>();
		for (String attrName : revealedAttributes.keySet())
			protoAttributes.put(attrName, revealedAttributes.get(attrName).toProto());
		Map<String, PabcSerializer.RangePredToken> protoTokens= new HashMap<>();
		for(String attrName:rangeTokens.keySet()){
			protoTokens.put(attrName,rangeTokens.get(attrName).toProto());
		}
		if (zkToken instanceof PSzkToken)
			return PabcSerializer.PresentationToken.newBuilder().setEpoch(epoch).setPsZkToken(((PSzkToken) zkToken).toProto())
				.putAllRevealedAttributes(protoAttributes).putAllRangePredTokens(protoTokens).build();
		else
			return PabcSerializer.PresentationToken.newBuilder().setEpoch(epoch).setPsZkTokenMod(((PSzkTokenModified) zkToken).toProto())
					.putAllRevealedAttributes(protoAttributes).putAllRangePredTokens(protoTokens).build();
	}

}
