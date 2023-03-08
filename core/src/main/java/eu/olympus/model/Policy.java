package eu.olympus.model;

import java.util.List;

public class Policy {

	private List<Predicate> predicates;
	private String policyId;

    public Policy(List<Predicate> predicates, String policyId) {
		super();
		this.predicates = predicates;
		this.policyId = policyId;
	}

	public Policy() {
    }

	public List<Predicate> getPredicates() {
		return predicates;
	}

	public void setPredicates(List<Predicate> predicates) {
		this.predicates = predicates;
	}

	public String getPolicyId() {
		return policyId;
	}

	public void setPolicyId(String policyId) {
		this.policyId = policyId;
	}
    
}
