plugins {
    `java-library`
    `maven-publish`
}

group = "io.kerosene.contracts"
version = "0.2.0-SNAPSHOT"
description = "Kerosene shared contracts for KFE/Core boundaries"

java {
    sourceCompatibility = JavaVersion.VERSION_21
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

repositories {
    mavenCentral()
}

publishing {
    publications {
        create<MavenPublication>("java") {
            from(components["java"])
        }
    }
}
