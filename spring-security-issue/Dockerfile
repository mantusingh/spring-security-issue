FROM tomcat:11.0.4-jdk17-temurin
EXPOSE 8080

# VOLUME /tmp
RUN ln -s /usr/local/tomcat /opt/tomcat && ln -s /usr/local/tomcat /opt/apache-tomcat-11.0.4
RUN  mkdir -p /opt/tomcat/webapps/spring-security-issue-1.0-SNAPSHOT/
COPY target/spring-security-issue-1.0-SNAPSHOT /opt/tomcat/webapps/spring-security-issue-1.0-SNAPSHOT
WORKDIR /opt/tomcat/bin/
ENTRYPOINT ["./catalina.sh","run"]