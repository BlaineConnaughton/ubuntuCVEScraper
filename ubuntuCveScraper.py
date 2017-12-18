import csv
import requests
import sys

try: 
    from BeautifulSoup import BeautifulSoup
except ImportError:
    from bs4 import BeautifulSoup

#This script should be run from the same location

CVElist = []

def scrape_ubuntu(cve , os_version , vulnpackage):
    # sample cve = 'CVE-2015-6240'

    pieces = cve.split("-")
    url = "https://people.canonical.com/~ubuntu-security/cve/%s/%s.html" % (pieces[1], cve)
    
    #get url and put into html parser library
    r = requests.get(url)
    soup = BeautifulSoup(r.content)
    
    container = soup.find('div', {'id': 'container'})
    priority = container.findAll('div')
    prio =  priority[0].text
    
    upstream , status = "Not found" , "Not found"

    #go to table and pull out the value matching os_version ex: 14.04
    packagediv = soup.findAll('div', {'class': 'pkg'})
    
    for packages in packagediv:
        if packages.find('div', {'class': 'value'}).text.find(vulnpackage) > -1:
            table = packages.findAll('table')
            rows = table[0].findAll('tr')
            for tr in rows:
                cols = tr.findAll('td')
                if cols[0].text.find('Upstream') > -1:
                    upstream = cols[1].text
                elif cols[0].text.find(os_version) > -1:
                    status = cols[1].text

            return url , prio , upstream , status 

    
    return url , prio , "Needs manual confirmation" , "Needs manual confirmation"


def main():
    
    if len(sys.argv) != 3:
        print "Usage: vulnUpdater.py example.csv osVersion"
        return

    filename = sys.argv[1]
    osversion = sys.argv[2]

    #First take in a CSV and read the values to build a list
    with open(filename, 'rU') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            item = (row['package'] , row['cve'])
            CVElist.append(item)
        print "Done reading in CSV"


    #Take the list built from the previous loop and start analyzing
    filename = "Updated-" + str(filename)

    with open(filename, 'w') as csvfile:
       
        #setup for the csv writer
        fieldnames = ['Package', 'CVE' , 'Priority' , "Upstream" , 'Version' , 'URL']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        #this i is to help track the results so people can see how far it has gone
        i = 0.00
        print "Starting to write csv: " + filename

        #domain name list we created from the previous CSV so we didn't have 2 csv objects open and writing
        for CVE in CVElist:
            i = i + 1
            package = CVE[0]
            cve = CVE[1]

            #This is a really basic progress bar
            if i % 25 == 0:
                print str(i/len(CVElist) * 100) + "%"


            url , prio , upstream , status = scrape_ubuntu(cve.strip() , osversion.strip(), package.strip())

            writer.writerow({'Package': package, "CVE" : cve , 'Priority': prio , 'Upstream': upstream , 'Version': status , 'URL': url })
            
            

if __name__ == "__main__":
    main()