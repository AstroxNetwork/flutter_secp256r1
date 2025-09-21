allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

val newBuildDir: Directory =
    rootProject.layout.buildDirectory
        .dir("../../build")
        .get()
rootProject.layout.buildDirectory.value(newBuildDir)

private val javaVersion = JavaVersion.VERSION_17

private val configureAndroidExtension: com.android.build.api.dsl.CommonExtension<*, *, *, *, *, *>.() -> Unit = {
    compileSdk = 36

    compileOptions {
        sourceCompatibility = javaVersion
        targetCompatibility = javaVersion
    }

    buildFeatures {
        buildConfig = true
    }
}

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)

    afterEvaluate {
        plugins.withId("org.gradle.java.base") {
            extensions.configure<JavaPluginExtension> {
                sourceCompatibility = javaVersion
                targetCompatibility = javaVersion
                toolchain {
                    languageVersion.set(JavaLanguageVersion.of(javaVersion.toString()))
                }
            }
        }

        plugins.withId("com.android.application") {
            project.extensions.configure<com.android.build.api.dsl.ApplicationExtension> {
                configureAndroidExtension()
                defaultConfig {
                    targetSdk = 36
                }
            }
        }

        plugins.withId("com.android.library") {
            project.extensions.configure<com.android.build.api.dsl.LibraryExtension> {
                configureAndroidExtension()
            }
        }

        tasks.withType<JavaCompile>().configureEach {
            sourceCompatibility = javaVersion.toString()
            targetCompatibility = javaVersion.toString()
        }

        tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
            compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.fromTarget(javaVersion.toString()))
        }
    }
}

subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
