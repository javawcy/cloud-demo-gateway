FROM openjdk:8-jdk-alpine
ADD /target/*.jar app.jar
EXPOSE 8080
RUN echo "Asia/Shanghai" > /etc/timezone;
USER root
CMD java -jar -Dspring.profiles.active=dev -Xms125M -Xmx256M /app.jar