
       


<?php

 // uploaded files directory

        $target_dir = "./user_feedback_submissions/";



        // rename before storing

        $fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);

        $target_file = $target_dir . $fileName;



        // get content headers

        $contentType = $_FILES['uploadFile']['type'];

        $MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);



        // blacklist test

        if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {

            echo "Extension not allowed";

            die();

        }



        // whitelist test

        if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {

            echo "Only images are allowed";

            die();

        }



        // type test

        foreach (array($contentType, $MIMEtype) as $type) {

            if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {

                echo "Only images are allowed";

                die();

            }

        }



        // size test

        if ($_FILES["uploadFile"]["size"] > 500000) {

            echo "File too large";

            die();

        }



        if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {

            displayHTMLImage($target_file);

        } else {

            echo "File failed to upload";

        }


function displayHTMLImage($imageFile)

{

    $type = mime_content_type($imageFile);



    switch ($type) {

        case 'image/jpg':

            echo "<img style=\"object-fit: contain; \" width='400' height='200' src='data:image/jpg;base64," . base64_encode(file_get_contents($imageFile)) . "'/>";

            break;

        case 'image/jpeg':

            echo "<img style=\"object-fit: contain; \" width='400' height='200' src='data:image/jpeg;base64," . base64_encode(file_get_contents($imageFile)) . "'/>";

            break;

        case 'image/png':

            echo "<img style=\"object-fit: contain; \" width='400' height='200' src='data:image/png;base64," . base64_encode(file_get_contents($imageFile)) . "'/>";

            break;

        case 'image/gif':

            echo "<img style=\"object-fit: contain; \" width='400' height='200' src='data:image/gif;base64," . base64_encode(file_get_contents($imageFile)) . "'/>";

            break;

        case 'image/svg+xml':

            libxml_disable_entity_loader(false);

            $doc = new DOMDocument();

            $doc->loadXML(file_get_contents($imageFile), LIBXML_NOENT | LIBXML_DTDLOAD);

            $svg = $doc->getElementsByTagName('svg');

            echo $svg->item(0)->C14N();

            break;

        default:

            echo "Image type not recognized";

    }

}