function zitateliste_aktionen_sort(key, desc){
    zitateliste_aktionen_data.sort(function (a, b){
        return a[key].localeCompare(b[key]);
    });
    if(desc){
        zitateliste_aktionen_data = zitateliste_aktionen_data.reverse();
    }
    zitateliste_aktionen_reload();
}
function zitateliste_aktionen_reload(){
    function $(id){return document.getElementById(id)}
    let inputs = ['text', 'changed', 'tags', 'time-start', 'time-end'];
    let ignored = [];
    for(let i=0; i < inputs.length; i++){
        let value = $('zitateliste-aktionen_search-input_' + inputs[i]).value;
        if(value !== ''){
            for(let j=0; j < zitateliste_aktionen_data.length; j++){
                if(ignored.includes(j)){/* pass */
                }else if(inputs[i] === 'time-start'){
                    if(zitateliste_aktionen_data[j]['time'].localeCompare(value) < 0){
                        ignored.push(j);
                    }
                }else if(inputs[i] === 'time-end'){
                    if(zitateliste_aktionen_data[j]['time'].localeCompare(value) > 0){
                        ignored.push(j);
                    }
                }else{
                    if(!(zitateliste_aktionen_data[j][inputs[i]].includes(value))){
                        ignored.push(j);
                    }
                }
            }
        }
    }
    let content = '';
    for(let i=0; i < zitateliste_aktionen_data.length; i++){
        if(!(ignored.includes(i))){
            let color = 'transparent';
            if(zitateliste_aktionen_data[i]['tags'].includes('geschützt')){
                color = '#9BF6FF'
            }if(zitateliste_aktionen_data[i]['tags'].includes('zensiert')){
                color = '#BDB2FF'
            }if(zitateliste_aktionen_data[i]['edited'].localeCompare(zitateliste_aktionen_last) > 0){
                color = '#FFADAD'
            }if(zitateliste_aktionen_data[i]['tags'].includes('problem')){
                color = '#FDFFB6'
            }
            content += `<li class="zitateliste_main-element"><div style="border: 4px solid ${color}; margin: 0;"><small>Aktion
<i>#${zitateliste_aktionen_data[i]['id']}</i> vom ${zitateliste_aktionen_data[i]['time']}</small>
<p class="zitateliste_main-element-text"><b>${zitateliste_aktionen_data[i]['text']}</b></p>
<p class="zitateliste_main-element-text">Tags: ${zitateliste_aktionen_data[i]['tags'].join(', ')}</p>
<small>Zuletzt bearbeitet am ${zitateliste_aktionen_data[i]['edited']} von ${zitateliste_aktionen_data[i]['changed']} &ensp;
<a href="/zitateliste/aktionen/geschichte/${zitateliste_aktionen_data[i]['id']}">Änderungsverlauf</a> &ensp;
<a href="/zitateliste/aktionen/bearbeiten/${zitateliste_aktionen_data[i]['id']}">Bearbeiten</a></small></div></li>`;
        }
    }
    $('zitateliste_aktionen_main').innerHTML = content;
}