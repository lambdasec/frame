plugins {
    `java-library`
}

repositories {
    mavenCentral()
}

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    api("com.google.code.gson:gson:2.9.0")
    implementation("org.apache.commons:commons-lang3:3.13.0")
}
