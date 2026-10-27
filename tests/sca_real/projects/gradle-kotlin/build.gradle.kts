plugins {
    java
}

repositories {
    mavenCentral()
}

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    implementation(project(":lib"))
    implementation("org.yaml:snakeyaml:1.33")
    // lib asks for gson 2.9.0; Gradle picks the higher version
    implementation("com.google.code.gson:gson:2.10.1")
    testImplementation("junit:junit:4.13.2")
}
