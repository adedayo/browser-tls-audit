package com.github.adedayo

import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.concurrent.atomic.AtomicInteger

import org.openqa.selenium.remote.{DesiredCapabilities, RemoteWebDriver}

import scala.collection.mutable.ListBuffer
import scala.io.Source

/**
  * @author Adedayo Adetoye
  * BrowserStack automation to drive TLS audit of browser versions
  */
object TLSAutomate extends App {

  /**
  Get config from file with this format
  <username>:<automation_key>
  <url_to_where_tlsaudit_service_lives>
  */
  val configFile = Source.fromFile("config.txt")
  val lines = configFile.getLines()
  val config = lines.next().split(":")
  val webpage = lines.next
  
  configFile.close()
  if (config.length == 2) {
    val username = config(0)
    val automate_key = config(1)
    val URL = "https://" + username + ":" + automate_key + "@hub-cloud.browserstack.com/wd/hub"
    val dateFormat = new SimpleDateFormat("dd-MM-yyyy")
    val name = "TLSAutomate7-" + dateFormat.format(new Date)

    val capabilities = Data.browsers.flatMap(b => b.getCapabilities).map(cap => {
      cap.setCapability("name", name)
      cap
    })

    val start = 1
    val count = new AtomicInteger(start)
    val len = capabilities.length
    capabilities.drop(start-1).par.foreach(cap => {
      try {
        val driver = new RemoteWebDriver(new URL(URL), cap)
        driver.get(webpage)
        Thread.sleep(100)
        println(s"${count.getAndIncrement()} of $len ${driver.getTitle}, ${cap.toString}")
        driver.quit()
      } catch {
        case x: Throwable =>
          println("Exception: ", x.getMessage)
          println("Sleeping for 3 minutes")
          Thread.sleep(3*60*1000)
      }
    })
    }


  }


  object Data {
    val emptyRange: Range = Range(0, 1).drop(1)
    val browsers = List(
      DesktopBrowser("Windows", "10", "Chrome", 37 to 75),
      DesktopBrowser("Windows", "10", "Firefox", 32 to 67),
      DesktopBrowser("Windows", "10", "Edge", 15 to 18),
      DesktopBrowser("Windows", "10", "IE", 11 to 11),

      DesktopBrowser("Windows", "8.1", "Chrome", 22 to 75),
      DesktopBrowser("Windows", "8.1", "Firefox", 32 to 67),
      DesktopBrowser("Windows", "8.1", "Edge", 15 to 18),
      DesktopBrowser("Windows", "8.1", "IE", 11 to 11),
      DesktopBrowser("Windows", "8.1", "Opera", emptyRange, List("12.15", "12.16")),

      DesktopBrowser("Windows", "8", "Chrome", 22 to 75),
      DesktopBrowser("Windows", "8", "Firefox", 16 to 67),
      DesktopBrowser("Windows", "8", "Opera", emptyRange, List("12.15", "12.16")),
      DesktopBrowser("Windows", "8", "IE", 10 to 10),

      DesktopBrowser("Windows", "7", "Chrome", 37 to 75),
      DesktopBrowser("Windows", "7", "Firefox", 32 to 67),
      DesktopBrowser("Windows", "7", "Opera", emptyRange, List("12.15", "12.16")),
      DesktopBrowser("Windows", "7", "IE", 8 to 11),

      DesktopBrowser("Windows", "XP", "Chrome", 14 to 47),
      DesktopBrowser("Windows", "XP", "Firefox", 4 to 47, List("3.6")),
      DesktopBrowser("Windows", "XP", "Opera", emptyRange, List("12.15", "12.16")),
      DesktopBrowser("Windows", "XP", "IE", 6 to 7),

      DesktopBrowser("OS X", "Mojave", "Chrome", 27 to 75),
      DesktopBrowser("OS X", "Mojave", "Firefox", 11 to 67),
      DesktopBrowser("OS X", "Mojave", "Opera", emptyRange, List("12.15")),
      DesktopBrowser("OS X", "Mojave", "Safari", emptyRange, List("12.1")),

      DesktopBrowser("OS X", "High Sierra", "Chrome", 27 to 75),
      DesktopBrowser("OS X", "High Sierra", "Firefox", 11 to 67),
      DesktopBrowser("OS X", "High Sierra", "Opera", emptyRange, List("12.15")),
      DesktopBrowser("OS X", "High Sierra", "Safari", emptyRange, List("11.1")),

      DesktopBrowser("OS X", "Sierra", "Chrome", 27 to 75),
      DesktopBrowser("OS X", "Sierra", "Firefox", 11 to 67),
      DesktopBrowser("OS X", "Sierra", "Opera", emptyRange, List("12.15")),
      DesktopBrowser("OS X", "Sierra", "Safari", emptyRange, List("10.1")),

      DesktopBrowser("OS X", "El Capitan", "Chrome", 14 to 75),
      DesktopBrowser("OS X", "El Capitan", "Firefox", 4 to 67),
      DesktopBrowser("OS X", "El Capitan", "Opera", emptyRange, List("12.15")),
      DesktopBrowser("OS X", "El Capitan", "Safari", emptyRange, List("9.1")),

      DesktopBrowser("OS X", "Yosemite", "Chrome", 14 to 75),
      DesktopBrowser("OS X", "Yosemite", "Firefox", 4 to 67, List("3.6")),
      DesktopBrowser("OS X", "Yosemite", "Opera", emptyRange, List("12.15")),
      DesktopBrowser("OS X", "Yosemite", "Safari", emptyRange, List("8.0")),

      DesktopBrowser("OS X", "Mavericks", "Chrome", 14 to 75),
      DesktopBrowser("OS X", "Mavericks", "Firefox", 4 to 67, List("3.6")),
      DesktopBrowser("OS X", "Mavericks", "Opera", emptyRange, List("12.15")),
      DesktopBrowser("OS X", "Mavericks", "Safari", emptyRange, List("7.1")),

      DesktopBrowser("OS X", "Mountain Lion", "Chrome", 14 to 49),
      DesktopBrowser("OS X", "Mountain Lion", "Firefox", 4 to 48, List("3.6")),
      DesktopBrowser("OS X", "Mountain Lion", "Opera", emptyRange, List("12.15")),
      DesktopBrowser("OS X", "Mountain Lion", "Safari", emptyRange, List("6.2")),


      DesktopBrowser("OS X", "Lion", "Chrome", 14 to 49),
      DesktopBrowser("OS X", "Lion", "Firefox", 4 to 43, List("3.6")),
      DesktopBrowser("OS X", "Lion", "Opera", emptyRange, List("12.15")),
      DesktopBrowser("OS X", "Lion", "Safari", emptyRange, List("6.0")),


      DesktopBrowser("OS X", "Snow Leopard", "Chrome", 14 to 49),
      DesktopBrowser("OS X", "Snow Leopard", "Firefox", 4 to 42),
      DesktopBrowser("OS X", "Snow Leopard", "Opera", emptyRange, List("12.15")),
      DesktopBrowser("OS X", "Snow Leopard", "Safari", emptyRange, List("5.1")),

      MobileBrowser("iPhone XS", "12"),
      MobileBrowser("iPhone XS Max", "12"),
      MobileBrowser("iPhone XR", "12"),
      MobileBrowser("iPhone X", "11"),
      MobileBrowser("iPhone 8", "12"),
      MobileBrowser("iPhone 8", "11"),
      MobileBrowser("iPhone 8 Plus", "11"),
      MobileBrowser("iPhone 7", "10"),
      MobileBrowser("iPhone 7 Plus", "10"),
      MobileBrowser("iPhone 6S", "12"),
      MobileBrowser("iPhone 6S", "11"),
      MobileBrowser("iPhone 6S Plus", "11"),
      MobileBrowser("iPhone 6", "11"),
      MobileBrowser("iPhone SE", "11"),

      MobileBrowser("iPad Pro 12.9 2018", "12"),
      MobileBrowser("iPad Pro 11 2018", "12"),
      MobileBrowser("iPad Pro 9.7 2016", "11"),
      MobileBrowser("iPad Pro 12.9 2017", "11"),
      MobileBrowser("iPad Mini 4", "11"),
      MobileBrowser("iPad 6th", "11"),
      MobileBrowser("iPad 5th", "11"),

      MobileBrowser("Samsung Galaxy S9 Plus", "9.0"),
      MobileBrowser("Samsung Galaxy S8 Plus", "9.0"),
      MobileBrowser("Samsung Galaxy S9 Plus", "8.0"),
      MobileBrowser("Samsung Galaxy Note 9", "8.1"),
      MobileBrowser("Samsung Galaxy S9", "8.0"),
      MobileBrowser("Samsung Galaxy Note 8", "7.1"),
      MobileBrowser("Samsung Galaxy A8", "7.1"),
      MobileBrowser("Samsung Galaxy S8 Plus", "7.0"),
      MobileBrowser("Samsung Galaxy S8", "7.0"),
      MobileBrowser("Samsung Galaxy S7", "6.0"),
      MobileBrowser("Samsung Galaxy Note 4", "6.0"),
      MobileBrowser("Samsung Galaxy S6", "5.0"),
      MobileBrowser("Samsung Galaxy Note 4", "4.4"),

      MobileBrowser("Samsung Galaxy Tab S4", "8.1"),
      MobileBrowser("Samsung Galaxy Tab S3", "8.0"),
      MobileBrowser("Samsung Galaxy Tab S3", "7.0"),
      MobileBrowser("Samsung Galaxy Tab 4", "4.4"),


      MobileBrowser("Google Pixel 3 XL", "9.0"),
      MobileBrowser("Google Pixel 3", "9.0"),

      MobileBrowser("Google Pixel 3 XL", "9.0"),
      MobileBrowser("Google Pixel 3 XL", "9.0"),
      MobileBrowser("Google Pixel 2", "9.0"),
      MobileBrowser("Google Pixel 2", "8.0"),
      MobileBrowser("Google Pixel", "8.0"),

      MobileBrowser("Google Pixel", "7.1"),
      MobileBrowser("Google Nexus 6", "6.0"),
      MobileBrowser("Google Nexus 6", "5.0"),
      MobileBrowser("Google Nexus 5", "4.4"),
      MobileBrowser("Motorola Moto X 2nd Gen", "6.0"),
      MobileBrowser("Motorola Moto X 2nd Gen", "5.0"),
      MobileBrowser("OnePlus 6T", "9.0"),
      MobileBrowser("Google Nexus 9", "5.1")
    )
  }


  abstract class Browser {
    def getCapabilities: List[DesiredCapabilities]
  }

  case class DesktopBrowser(OS: String, OSVersion: String, Browser: String, BrowserVersions: Range, AdditionalVersions: List[String] = List.empty[String]) extends Browser {
    override def getCapabilities: List[DesiredCapabilities] = {
      val caps = ListBuffer.empty[DesiredCapabilities]

      (BrowserVersions.reverse.map(x => s"$x.0") ++ AdditionalVersions).map(v => {
        val cap = new DesiredCapabilities()
        cap.setCapability("os", OS)
        cap.setCapability("os_version", OSVersion)
        cap.setCapability("browser", Browser)
        cap.setCapability("browser_version", v)
        cap.setCapability("browserstack.local", "false")
        cap
      }).toList
    }
  }

  case class MobileBrowser(Device: String, OSVersion: String) extends Browser {
    override def getCapabilities: List[DesiredCapabilities] = {
      val cap = new DesiredCapabilities()
      cap.setCapability("device", Device)
      cap.setCapability("os_version", OSVersion)
      cap.setCapability("real_mobile", "true")
      cap.setCapability("browserstack.local", "false")
      List(cap)
    }
  }
