module ca.j0e.passwordmanager {
    requires javafx.controls;
    requires javafx.fxml;


    opens ca.j0e.passwordmanager to javafx.fxml;
    exports ca.j0e.passwordmanager;
}
