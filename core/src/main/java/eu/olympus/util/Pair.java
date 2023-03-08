package eu.olympus.util;

import java.util.Objects;

public class Pair<T, U> {
    private final T t;
    private final U u;

    public Pair(T t, U u) {
        this.t= t;
        this.u= u;
    }

    public T getFirst() {
        return t;
    }

    public U getSecond() {
        return u;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
        	return true;
        }
        if (o == null) {
        	return false;
        }
        if( getClass() != o.getClass()) {
        	return false;
        }
        Pair<?, ?> pair = (Pair<?, ?>) o;
        return Objects.equals(t, pair.t) &&
                Objects.equals(u, pair.u);
    }

}