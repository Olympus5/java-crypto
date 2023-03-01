package fr.olympus5.bean;

import java.io.Serializable;

public class Person implements Serializable {
    private final int id;
    private final String firstname;
    private final String lastname;

    public Person(final int id, final String lastname, final String firstname) {
        this.id = id;
        this.firstname = firstname;
        this.lastname = lastname;
    }

    public int getId() {
        return id;
    }

    public String getFirstname() {
        return firstname;
    }

    public String getLastname() {
        return lastname;
    }

    @Override
    public String toString() {
        return "Person{" +
                "id=" + id +
                ", firstname='" + firstname + '\'' +
                ", lastname='" + lastname + '\'' +
                '}';
    }
}
