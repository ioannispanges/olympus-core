package eu.olympus.model;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Basically a wrapper for ChronoUnit to restrict the supported granularities to the ones that should be useful for us.
 */
public enum DateGranularity {

    MILLIS("Milliseconds",ChronoUnit.MILLIS),
    SECONDS("Seconds",ChronoUnit.SECONDS),
    MINUTES("Minutes",ChronoUnit.MINUTES),
    HOURS("Hours",ChronoUnit.HOURS),
    DAYS("Days",ChronoUnit.DAYS);


    private final String name;
    private final ChronoUnit unit;


    private DateGranularity(String name, ChronoUnit unit) {
        this.name = name;
        this.unit = unit;
    }

    public ChronoUnit getUnit() {
        return unit;
    }

    public long between(Instant begin, Instant end){
        return unit.between(begin,end);
    }
}
