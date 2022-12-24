function zitateliste_sort(key, desc){
    zitateliste_data.sort(function (a, b){
        return a[key].localeCompare(b[key]);
    });
    if(desc){
        zitateliste_data = zitateliste_data.reverse();
    }
    zitateliste_reload();
}
function zitateliste_reload(){
    function $(id){return document.getElementById(id)}
    let inputs = ['text', 'author', 'changed', 'tags', 'time-start', 'time-end'];
    let ignored = [];
    for(let i=0; i < inputs.length; i++){
        let value = $('zitateliste_search-input_' + inputs[i]).value;
        if(value !== ''){
            for(let j=0; j < zitateliste_data.length; j++){
                if(ignored.includes(j)){/* pass */
                }else if(inputs[i] === 'time-start'){
                    if(zitateliste_data[j]['time'].localeCompare(value) < 0){
                        ignored.push(j);
                    }
                }else if(inputs[i] === 'time-end'){
                    if(zitateliste_data[j]['time'].localeCompare(value) > 0){
                        ignored.push(j);
                    }
                    /*}else if(inputs[i] === 'tags'){
                           if(!(zitateliste_data[j][inputs[i]].includes(value))){
                               ignored.push(j);
                           }*/
                }else{
                    if(!(zitateliste_data[j][inputs[i]].includes(value))){
                        ignored.push(j);
                    }
                }
            }
        }
    }
    let content = '';
    for(let i=0; i < zitateliste_data.length; i++){
        if(!(ignored.includes(i))){
            let color = 'transparent';
            if(zitateliste_data[i]['tags'].includes('geschützt')){
                color = '#9BF6FF'
            }if(zitateliste_data[i]['tags'].includes('zensiert')){
                color = '#BDB2FF'
            }if(zitateliste_data[i]['edited'].localeCompare(zitateliste_last) > 0){
                color = '#FFADAD'
            }if(zitateliste_data[i]['tags'].includes('problem')){
                color = '#FDFFB6'
            }
            content += `<li class="zitateliste_main-element"><div style="border: 4px solid ${color}; margin: 0;"><small>Zitat
<i>#${zitateliste_data[i]['id']}</i> vom ${zitateliste_data[i]['time']}</small>
<p class="zitateliste_main-element-text"><b>${zitateliste_data[i]['text'].replaceAll(';', ' – ')}</b></p>
<p class="zitateliste_main-element-text"><b>~${zitateliste_data[i]['author'].replaceAll(';', ' – ')}</b></p>
<p class="zitateliste_main-element-text"><i>${zitateliste_data[i]['comments']}</i></p>
<p class="zitateliste_main-element-text">Tags: ${zitateliste_data[i]['tags'].join(', ')}</p>
<small>Zuletzt bearbeitet am ${zitateliste_data[i]['edited']} von ${zitateliste_data[i]['changed']} &ensp;
<a href="/zitateliste/zitate/geschichte/${zitateliste_data[i]['id']}">Änderungsverlauf</a> &ensp;
<a href="/zitateliste/zitate/bearbeiten/${zitateliste_data[i]['id']}">Bearbeiten</a></small></div></li>`;
        }
    }
    $('zitateliste_main').innerHTML = content;
}