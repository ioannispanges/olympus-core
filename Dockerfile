FROM maven:3.8.3-jdk-8

COPY . .

RUN ["mvn", "-f", "/core/pom.xml", "clean"]

CMD ["mvn", "-f", "/core/pom.xml", "install"]
