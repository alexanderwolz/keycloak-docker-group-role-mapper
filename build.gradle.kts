plugins {
    kotlin("jvm") version "2.0.0"
    application
}

group = "de.alexanderwolz"
version = "1.7.0"

val keycloakVersion = "26.1.0"
val keycloakJdkVersion = 21 //Keycloak 25 relies on JDK 21

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("org.keycloak:keycloak-core:$keycloakVersion")
    compileOnly("org.keycloak:keycloak-services:$keycloakVersion")
    compileOnly("org.keycloak:keycloak-server-spi:$keycloakVersion")
    compileOnly("org.keycloak:keycloak-server-spi-private:$keycloakVersion")
    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.1.0")
    testImplementation("org.keycloak:keycloak-core:$keycloakVersion")
    testImplementation("org.keycloak:keycloak-services:$keycloakVersion")
    testImplementation("org.keycloak:keycloak-server-spi:$keycloakVersion")
    testImplementation("org.keycloak:keycloak-server-spi-private:$keycloakVersion")
}

tasks.test {
    useJUnitPlatform()
    systemProperty("java.util.logging.config.file", "${projectDir}/src/test/resources/logging.properties")
}

kotlin {
    jvmToolchain(keycloakJdkVersion)
}

//create fat jar
//TODO remove and just add org.jetbrains.kotlin:kotlin-stdlib
tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations
        .runtimeClasspath
        .get()
        .map { if (it.isDirectory) it else zipTree(it) }
    )
}