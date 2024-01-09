FROM mcr.microsoft.com/vscode/devcontainers/java:17
ARG GRADLE_VERSION
ARG SPRING_VERSION
RUN su vscode -c "umask 0002 && . /usr/local/sdkman/bin/sdkman-init.sh && sdk install gradle \"${GRADLE_VERSION}\" && sdk install springboot \"${SPRING_VERSION}\""


