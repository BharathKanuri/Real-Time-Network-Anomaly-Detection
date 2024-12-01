async function startSniffing(){
    const tbody=document.getElementById("results-table").querySelector("tbody")
    try{
        // Send Request to Start Sniffing
        const response=await fetch('/start',{method:'POST'})
        const result=await response.json()
        if(result.status==="started"){
            // Display "Sniffing Packets..." Message
            tbody.innerHTML="<tr><td colspan='6' style='text-align:center; color: green'>Sniffing Packets...</td></tr>"
        }
    }
    catch(error){
        tbody.innerHTML="<tr><td colspan='6' style='text-align:center; color:red'>Please Start Server or Check Network Connection...</td></tr>"
    }
}
async function stopSniffing(){
    const tbody=document.getElementById("results-table").querySelector("tbody")
    try{
        // Send Request to Stop Sniffing
        const response=await fetch('/stop',{method:'POST'})
        const result=await response.json()
        if(result.status==="stopped"){
            const data=result.data
            // Clear "Sniffing Packets..." Message
            tbody.innerHTML=""
            // Populate the Table with Packet Data
            data.forEach(row=>{
                const tr=document.createElement("tr")
                const color=row.prediction==="Normal"?"green":"red"
                const backgroundColor=row.prediction==="Normal"?"#CCFEFF":"#FFCCCB"
                tr.style.backgroundColor=backgroundColor
                tr.innerHTML=`<td>${row.timestamp}</td>
                              <td>${row.src_ip}</td>
                              <td>${row.dst_ip}</td>
                              <td>${row.protocol}</td>
                              <td style="color:${color}">${row.prediction}</td>`
                tr.addEventListener("mouseover",()=>{
                    tr.style.backgroundColor="#FFFFFF"
                })
                tr.addEventListener("mouseout",()=>{
                    tr.style.backgroundColor=backgroundColor
                })
                tbody.appendChild(tr)
            })
        }
    }
    catch(error){
        tbody.innerHTML="<tr><td colspan='6' style='text-align:center; color:red'>Please Start Server or Check Network Connection...</td></tr>"
    }
}
async function generateReport(){
    try{
        // Send Request to Generate and Download Report
        const response=await fetch('/generate-report',{method:'POST'})
        const result=await response.json()
        if(result.status==="success"){
            // Create a Download Link and Simulate Click to Download the Report
            const link=document.createElement('a')
             // URL for the File
            link.href=result.file_url
            document.body.appendChild(link)
            link.click()
            document.body.removeChild(link)
        }
    }
    catch(error){
        alert("Error in Generating Report: "+error)
    }
}