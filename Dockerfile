FROM maven:3.9.9-amazoncorretto

COPY . .

RUN mvn clean package -DskipTests 

FROM openjdk:19

WORKDIR /app

ARG JAR_FILE=target/*.jar

COPY ${JAR_FILE} /app/cybereduc_api.jar

ENTRYPOINT ["java", "-jar", "/app/cybereduc_api.jar"]