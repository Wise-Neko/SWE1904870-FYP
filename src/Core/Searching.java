package Core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.util.io.Base64;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Searching {
    public static String[] org;
    public static String[] loc;
    public static String[] mon;
    public static String[] yrs;
    public static String[] tok;

    public static void indexLoad(String organization, String locations, String months, String years, String token){
        org = organization.split(",");
        loc = locations.split(",");
        mon = months.split(",");
        yrs = years.split(",");
        tok = token.split(",");
    }

    public static Integer[] searchIndex(String organization, String locations, String months, String years){
        List<Integer> indexList = new ArrayList<Integer>();
        List<Integer> orgList = new ArrayList<Integer>();
        List<Integer> locList = new ArrayList<Integer>();
        List<Integer> monList = new ArrayList<Integer>();
        List<Integer> yrsList = new ArrayList<Integer>();

        boolean flag = false;

        if(!organization.equals("NULL"))
        {
            int counter = 0;
            for(int i = 0; i < org.length ; i++){
                if(org[i].equals(organization))
                    if(!orgList.contains(i)) {
                        orgList.add(i);
                        counter++;
                    }
            }
            if(counter == 0)
                flag = true;
        }else
            orgList = null;

        if(!locations.equals("NULL") && !flag)
        {
            int counter = 0;
            for(int i = 0; i < loc.length ; i++){
                if(loc[i].equals(locations))
                    if(!locList.contains(i)) {
                        locList.add(i);
                        counter++;
                    }
            }
            if(counter == 0)
                flag = true;
        }else
            locList = null;

        if(!months.equals("NULL") && !flag)
        {
            int counter = 0;
            for(int i = 0; i < mon.length ; i++){
                if(mon[i].equals(months))
                    if(!monList.contains(i)) {
                        monList.add(i);
                        counter++;
                    }
            }
            if(counter == 0)
                flag = true;
        }else
            monList = null;

        if(!years.equals("NULL") && !flag)
        {
            int counter = 0;
            for(int i = 0; i < yrs.length ; i++){
                if(yrs[i].equals(years))
                    if(!yrsList.contains(i)) {
                        yrsList.add(i);
                        counter++;
                    }
            }
            if(counter == 0)
                flag = true;
        }else
            yrsList = null;

        List<Integer>[] arrayList = new List[4];
        arrayList[0] = orgList;
        arrayList[1] = locList;
        arrayList[2] = monList;
        arrayList[3] = yrsList;

        if(!flag)
        {
            boolean inputFlag = false;
            for(int i = 0; i < 4; i++)
            {
                if(!inputFlag && arrayList[i] != null)
                {
                    indexList = arrayList[i];
                    inputFlag = true;
                }

                if(arrayList[i] != null)
                    indexList.retainAll(arrayList[i]);
                    System.out.println(arrayList);
                    System.out.println(indexList);
            }
        } else
        {
            indexList.add(-1);
        }

        Integer[] index = new Integer[indexList.size()];
        index = indexList.toArray(index);
        return index;
    }

    public static Integer[] tokenCompare(PublicKey pub, Token token, Integer[] position) throws IOException {
        List<Integer> checkList = new ArrayList<Integer>();
        for(int i = 0; i < position.length; i++)
        {
            boolean result = false;
            String[] tokenString = tok[position[i]].split(";");
            System.out.println(tokenString[0] + "\n" + tokenString[1] + "\n" + tokenString[2]);
            result = ABSE.search(pub, token, tokenString);
            if(result)
                checkList.add(i);
        }
        Integer[] desiredPos = new Integer[checkList.size()];
        desiredPos = checkList.toArray(desiredPos);
        return desiredPos;
    }
}
