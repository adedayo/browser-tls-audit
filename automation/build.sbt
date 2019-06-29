ThisBuild / scalaVersion := "2.12.7"
ThisBuild / organization := "com.github.adedayo"

lazy val TLSAutomate = (project in file("."))
  .settings(
    name := "TLSAutomate",
    libraryDependencies += "org.seleniumhq.selenium" % "selenium-java" % "3.141.59"
  )