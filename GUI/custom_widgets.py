from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon
import re
import qtawesome as qta
from MyLibs.brains import *
import sys
import os


class Login(QDialog):
    """
    Login/Registration window, for logging in or registering :)
    """
    def __init__(self, login_func, register_func, parent=None,):
        super(Login, self).__init__(parent)
        self.setWindowIcon(QIcon('logo.png'))

        self.setWindowTitle("Welcome!")
        name_layout = QHBoxLayout()
        pass_layout = QHBoxLayout()
        self.text_name = QLineEdit(self)
        self.text_pass = QLineEdit(self)
        icon_name = qta.IconWidget()
        icon_name.setIcon(qta.icon('mdi.account-circle',color='white'))
        icon_pass = qta.IconWidget()
        icon_pass.setIcon(qta.icon('mdi.key-variant',color='white'))
        name_layout.addWidget(icon_name)
        name_layout.addWidget(self.text_name)
        pass_layout.addWidget(icon_pass)
        pass_layout.addWidget(self.text_pass)

        self.button_login = QPushButton('Login', self)
        self.button_login.clicked.connect(lambda: self.handleLogin(login_func))
        self.button_register = QPushButton('Register', self)
        self.button_register.clicked.connect(lambda: self.handleRegister(register_func))
        main_layout = QVBoxLayout(self)

        self.frame = QFrame()
        self.frame.setFrameShape(QFrame.StyledPanel)
        #self.frame.setContentsMargins(200,300,200,300)
        self.frame.resize(300,300)
        layout = QVBoxLayout(self.frame)
        layout.addLayout(name_layout)
        layout.addLayout(pass_layout)
        layout.addWidget(self.button_login)
        layout.addWidget(self.button_register)

        layout.setContentsMargins(150,100,150,100)
        main_layout.addWidget(self.frame)
      

        if not start_tcp():
            QMessageBox.warning(self, 'Error', 'TCP Connection unsuccessful. Closing program, try again.')
            sys.exit()

    def handleLogin(self,login_func):
        """
        Based on login_func in brains module (checks SQL database), go to accepted state if login values are correct 
        """
        if login_func(self.text_name.text(), self.text_pass.text()):
            send_username(self.text_name.text())
            self.accept()
        else:
            QMessageBox.warning(self, 'Error', 'Bad user or password')

    def handleRegister(self,register_func):
        """
        Based on register_func in brains module (checks SQL database), go to accepted state if registration is possible given the registration values
        """
        if not self.text_name.text() or not self.text_pass.text():
            QMessageBox.warning(self, 'Registration Error', 'Please fill out the form completely!')
        elif not re.match(r'[A-Za-z0-9]+', self.text_name.text()):
            QMessageBox.warning(self, 'Registration Error', 'Username must contain only characters and numbers!')
        elif self.text_pass.text().find("'") != -1 or self.text_pass.text().find('"') != -1 or self.text_pass.text().find('=') != -1 or self.text_pass.text().find(';') != -1:
            QMessageBox.warning(self, 'Registration Error', 'No SQLInjection please')
        elif len(self.text_name.text()) >50:
            QMessageBox.warning(self, 'Registration Error', 'Max username length 50 chars')
        elif len(self.text_pass.text()) >255:
            QMessageBox.warning(self, 'Registration Error', 'Max password length 255 chars')            
        elif register_func(self.text_name.text(), self.text_pass.text()):
            send_username(self.text_name.text())
            self.accept()
        else:
            QMessageBox.warning(self, 'Registration Error', 'Account already exists')

class RepoCreate(QDialog):
    """
    Window for creating a repository, with choice of linked accounts and files
    """
    def __init__(self, window, parent=None,):
        super(RepoCreate, self).__init__(parent)
        self.setWindowTitle("Create Repository")
        self.parentWindow = window
        #Allocation of repo variables, as to not cause missing-variable errors (because later it is possible to not select anything for some variables and so they would not be created otherwise)
        self.files = None
        self.directory = None
        self.local_directory = None
        repo_name = QHBoxLayout()
        name_label = QLabel("Repository Name:")
        self.name_entry = QLineEdit()
        repo_name.addWidget(name_label)
        repo_name.addWidget(self.name_entry)
       
        account_label = QLabel("Linked Accounts")
        comments_label = QLabel("Project Description")


        self.button_files = QPushButton('Add Files', self)
        self.button_files.clicked.connect(self.handle_files)
        self.button_directory = QPushButton('Add Directory', self)
        self.button_directory.clicked.connect(self.handle_directory)
        self.button_directory_location = QPushButton('Choose Local Repo Working Directory', self)
        self.button_directory_location.clicked.connect(self.handle_repo_directory)

        self.user_list = QListWidget()
        self.user_list.addItems(get_users())
        self.user_list.setSelectionMode(QAbstractItemView.MultiSelection)

        self.repo_description = QPlainTextEdit()

        self.button_create = QPushButton('Create', self)
        self.button_create.clicked.connect(self.handleCreate)

        main_layout = QVBoxLayout(self)

        self.frame = QFrame()
        self.frame.setFrameShape(QFrame.StyledPanel)
        
        layout = QVBoxLayout(self.frame)
        layout.addLayout(repo_name)
        users_comments_layout = QHBoxLayout()
        users_layout = QVBoxLayout()
        users_layout.addWidget(account_label)
        users_layout.addWidget(self.user_list)
        users_comments_layout.addLayout(users_layout)
        comments_layout = QVBoxLayout()
        comments_layout.addWidget(comments_label)
        comments_layout.addWidget(self.repo_description)
        users_comments_layout.addLayout(comments_layout)


        layout.addLayout(users_comments_layout)
        layout.addWidget(self.button_files)
        layout.addWidget(self.button_directory)
        layout.addWidget(self.button_directory_location)
        layout.addWidget(self.button_create)  

        main_layout.addWidget(self.frame)
     

        
    def handleCreate(self):
        """
        Using function in brains module, notify server of created repository
        """
        #do things to server
        if (self.name_entry.text() == ""):
            QMessageBox.warning(self, 'Creation Error', 'Repository Name Required')
            return
        elif(self.local_directory == None):
            QMessageBox.warning(self, 'Creation Error', 'Local Repository Location Required')
            return

        linked_users = []
        for obj in self.user_list.selectedItems(): linked_users.append(obj)
        create_repo(self.files, self.directory,self.local_directory,linked_users,self.name_entry.text(),self.repo_description.toPlainText()) #From brains module
        self.parentWindow.reload()
        self.close()

        

    def handle_files(self):
        """
        This method updates the file list with chosen files
        """
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFiles)
        if file_dialog.exec_():
            self.files = file_dialog.selectedFiles()
        else:
            self.files = None
        
    def handle_directory(self):
        """
        This method updates the directory list with chosen directories
        """
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.Directory)
        if file_dialog.exec_():
            self.directory = file_dialog.selectedFiles()
        else:
            self.directory = None

    def handle_repo_directory(self):
        """
        This method updates the list of the directory chosen to contain the repository
        """
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.Directory)
        if file_dialog.exec_():
            self.local_directory = file_dialog.selectedFiles()
        else:
            self.local_directory = None

class CommitDialog(QDialog):
    """
    Window for commiting changes in current repository (in branch of choice)
    """
    def __init__(self, window, parent=None,):
        super(CommitDialog, self).__init__(parent)
        self.setWindowTitle("Commit Changes")
        self.parentWindow = window
        #Allocation of commit-files variables, as to not cause missing-variable errors (because later it is possible to not select anything for some variables and so they would not be created otherwise)
        self.files = None
        self.directory = None
       
        branch_label = QLabel("Choose Branch")
        comments_label = QLabel("Commit Description")

        title_label = QLabel("Commit Title:")
        self.title_entry = QLineEdit()



        self.branch_list = QListWidget()
        self.branch_list.addItems(get_branches())
        
        self.commit_description = QPlainTextEdit()

        self.button_commit = QPushButton('Commit', self)
        self.button_commit.clicked.connect(self.handle_commit)
        self.button_files = QPushButton('Add Files', self)
        self.button_files.clicked.connect(self.handle_files)
        self.button_directory = QPushButton('Add Directory', self)
        self.button_directory.clicked.connect(self.handle_directory)

        
        main_layout = QVBoxLayout(self)

        self.frame = QFrame()
        self.frame.setFrameShape(QFrame.StyledPanel)
        
        layout = QVBoxLayout(self.frame)

        title_layout = QHBoxLayout()
        title_layout.addWidget(title_label)
        title_layout.addWidget(self.title_entry)

        users_comments_layout = QHBoxLayout()
        users_layout = QVBoxLayout()
        users_layout.addWidget(branch_label)
        users_layout.addWidget(self.branch_list)
        users_comments_layout.addLayout(users_layout)
        comments_layout = QVBoxLayout()
        comments_layout.addWidget(comments_label)
        comments_layout.addWidget(self.commit_description)
        users_comments_layout.addLayout(comments_layout)

        layout.addLayout(title_layout)
        layout.addLayout(users_comments_layout)
        layout.addWidget(self.button_files)
        layout.addWidget(self.button_directory)
        layout.addWidget(self.button_commit)

        main_layout.addWidget(self.frame)  
        
    def handle_commit(self):
        """
        This method checks if all data for the commit has been filled out,
        and summons the commit function if they were (and updates the user about the success of the commit)
        """
        if(self.title_entry.text()==""):
            QMessageBox.warning(self, 'Creation Error', 'Title Entry Required')
            return
        if (self.branch_list.selectedItems()== []):
            QMessageBox.warning(self, 'Creation Error', 'Branch Selection Required')
            return
        success = commit(self.branch_list.selectedItems()[0].text(), self.files, self.directory, self.title_entry.text(), self.commit_description.toPlainText())
        if success:
            message = QMessageBox.information(self, 'Commit Success', 'Changes Committed Successfully')
            self.parentWindow.reload()
        else:
            message = QMessageBox.information(self, 'Commit on Hold', 'Changes Awaiting Owner Confirmation')
        self.close()


    
    def handle_files(self):
        """
        This method updates the list with all the selected files
        """
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFiles)
        if file_dialog.exec_():
            self.files = file_dialog.selectedFiles()
        else:
            self.files = None
        
    def handle_directory(self):
        """
        This method updates the list with all directories chosen by the user
        """
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.Directory)
        if file_dialog.exec_():
            self.directory = file_dialog.selectedFiles()
        else:
            self.directory = None


class BranchDialog(QDialog):
    """
    Window for creating a new branch in the repository
    """
    def __init__(self, window, parent=None,):
        super(BranchDialog, self).__init__(parent)
        self.setWindowTitle("Branch Out")
        self.parentWindow = window
        #Allocation of commit-files variables, as to not cause missing-variable errors (because later it is possible to not select anything for some variables and so they would not be created otherwise)
        self.files = None
        self.directory = None

        branch_choose_label = QLabel("Choose Parent Branch")

        branch_label = QLabel("Branch Name:")
        self.branch_entry = QLineEdit()

        
        self.branch_list = QListWidget()
        self.branch_list.addItems(get_branches())
        

        self.button_create = QPushButton('Create', self)
        self.button_create.clicked.connect(self.handle_branch)
        self.button_files = QPushButton('Add Files', self)
        self.button_files.clicked.connect(self.handle_files)
        self.button_directory = QPushButton('Add Directory', self)
        self.button_directory.clicked.connect(self.handle_directory)

        
        main_layout = QVBoxLayout(self)

        self.frame = QFrame()
        self.frame.setFrameShape(QFrame.StyledPanel)
        
        layout = QVBoxLayout(self.frame)

        title_layout = QHBoxLayout()
        title_layout.addWidget(branch_label)
        title_layout.addWidget(self.branch_entry)

        branch_layout = QVBoxLayout()
        branch_layout.addWidget(branch_choose_label)
        branch_layout.addWidget(self.branch_list)

        layout.addLayout(title_layout)
        layout.addLayout(branch_layout)
        layout.addWidget(self.button_files)
        layout.addWidget(self.button_directory)
        layout.addWidget(self.button_create)

        main_layout.addWidget(self.frame) 
        
    def handle_branch(self):
        """
        This method summons the branch creation command with the selected branch and files (if indeed a branch was chosen)
        """
        if (self.branch_list.selectedItems()== []):
            QMessageBox.warning(self, 'Creation Error', 'Branch Selection Required')
            return
        create_branch(self.branch_list.selectedItems()[0].text(), self.files, self.directory, self.branch_entry.text())
        self.parentWindow.reload()
        self.close()

    
    def handle_files(self):
        """
        This method updates the list with all files chosen by the user
        """
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFiles)
        if file_dialog.exec_():
            self.files = file_dialog.selectedFiles()
        else:
            self.files = None
        
    def handle_directory(self):
        """
        This method updates the list with directory chosen by the user
        """
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.Directory)
        if file_dialog.exec_():
            self.directory = file_dialog.selectedFiles()
        else:
            self.directory = None


class MergeDialog(QDialog):
    """
    Window for sending a merge request to the server
    """
    def __init__(self, window, parent=None,):
        super(MergeDialog, self).__init__(parent)
        self.setWindowTitle("Merge Branches")
        self.parentWindow = window
        #Allocation of commit-files variables, as to not cause missing-variable errors (because later it is possible to not select anything for some variables and so they would not be created otherwise)
        self.files = None
        self.directory = None
       
        branch_label = QLabel("Choose Branch")

        title_label = QLabel("Version Title after Merge:")
        self.title_entry = QLineEdit()

        self.branch_list = QListWidget()
        self.branch_list.addItems(get_branches())
        
        self.button_merge = QPushButton('Merge', self)
        self.button_merge.clicked.connect(self.handle_merge)
        

        
        main_layout = QVBoxLayout(self)

        self.frame = QFrame()
        self.frame.setFrameShape(QFrame.StyledPanel)
        
        layout = QVBoxLayout(self.frame)

        title_layout = QHBoxLayout()
        title_layout.addWidget(title_label)
        title_layout.addWidget(self.title_entry)

        branch_layout = QVBoxLayout()
        branch_layout.addWidget(branch_label)
        branch_layout.addWidget(self.branch_list)

        layout.addLayout(title_layout)
        layout.addLayout(branch_layout)

        layout.addWidget(self.button_merge)

        main_layout.addWidget(self.frame)   
        
    def handle_merge(self):
        """
        This method checks if a branch was selected, summons the merge function, and informs user about merge success
        """
        if (self.branch_list.selectedItems()== []):
            QMessageBox.warning(self, 'Creation Error', 'Branch Selection Required')
            return
        success = merge(self.branch_list.selectedItems()[0].text(), self.title_entry.text())
        if success:
            message = QMessageBox.information(self, 'Merge Success', 'Branches Merged Successfully')
            self.parentWindow.reload()
        else:
            message = QMessageBox.information(self, 'Commit on Hold', 'Merge Awaiting Owner Confirmation')
        self.close()

    


class RepoChoose(QDialog):
    """
    Window for choosing a new repository
    """
    def __init__(self,window, parent=None,):
        super(RepoChoose, self).__init__(parent)
        self.setWindowTitle("Choose Repository")
        self.parentWindow = window
        #Allocation of repo-directory variable, as to not cause missing-variable errors (because later it is possible to not select anything for some variables and so they would not be created otherwise)
        self.directory = None
       
        self.repo_label = QLabel("Choose Repository")

        self.repo_list = QListWidget()
        self.repo_list.addItems(get_repos())
        
        self.button_choose = QPushButton('Choose', self)
        self.button_choose.clicked.connect(self.handle_choice)
        
        self.button_directory = QPushButton('Choose Directory', self)
        self.button_directory.clicked.connect(self.handle_directory)

        
        main_layout = QVBoxLayout(self)

        self.frame = QFrame()
        self.frame.setFrameShape(QFrame.StyledPanel)
        layout = QVBoxLayout(self.frame)

        layout.addWidget(self.repo_label)
        layout.addWidget(self.repo_list)
        layout.addWidget(self.button_directory)
        layout.addWidget(self.button_choose)

        main_layout.addWidget(self.frame)
    
    def handle_choice(self):
        """
        This  checks if all data was filled out, and summons the repository change function with the selected data
        """
        if (self.repo_list.selectedItems()== []):
            QMessageBox.warning(self, 'Choice Error', 'Repository Selection Required')
            return
        if (self.directory == None):
            QMessageBox.warning(self, 'Choice Error', 'Directory Selection Required')
            return
        repo_location(self.directory, self.repo_list.selectedItems()[0].text())
        self.parentWindow.reload()
        self.close()

    def handle_directory(self):
        """
        This method updates the directory list with the directory chosen by the user.
        """
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.Directory)
        if file_dialog.exec_():
            self.directory = file_dialog.selectedFiles()
        


class Window(QMainWindow):
    """
    Main program window
    """
    def __init__(self, parent=None):
        super(Window, self).__init__(parent)
        self.directory = None
        self.repo_dict = repo_details()
        self.repo = self.repo_dict["Repo"]
        self.parent_path = os.path.join("C:\\RepoServer",self.repo)
        description = get_description()
        self.description_label = QLabel("Description: \n" + description)

        self.setWindowIcon(QIcon('logo.png'))

        main_widget = QWidget()
        self.setWindowTitle("David's Git-alike")

        view_label = QLabel("Project View")

        self.button_create_repo = QPushButton('Create Repository', self)
        self.button_create_repo.clicked.connect(self.repo_create)

        self.button_commit = QPushButton('Commit Changes', self)
        self.button_commit.clicked.connect(self.commit)

        self.button_comment = QPushButton('Get Commit Comment', self)
        self.button_comment.clicked.connect(self.get_comment)

        self.button_branch = QPushButton('New Branch', self)
        self.button_branch.clicked.connect(self.branch)

        self.repo_directory = QPushButton('Change Repository', self)
        self.repo_directory.clicked.connect(self.repo_location)

        self.button_merge = QPushButton('Merge Branches', self)
        self.button_merge.clicked.connect(self.merge_func)

        self.button_check = QPushButton('Check for Requests', self)
        self.button_check.clicked.connect(self.check_requests)

        self.button_reload = QPushButton('Reload', self)
        self.button_reload.clicked.connect(self.reload)

        self.button_download = QPushButton('Download', self)
        self.button_download.clicked.connect(self.download)

        self.button_select = QPushButton('Select', self)
        self.button_select.clicked.connect(self.select)

        self.button_back = QPushButton('Back', self)
        self.button_back.clicked.connect(self.back)

        self.button_download_path = QPushButton('Download Location', self)
        self.button_download_path.clicked.connect(self.download_path)
        
        main_layout = QVBoxLayout(main_widget)

        self.layout_organizer = QHBoxLayout()

        self.frame2 = QFrame()
        self.frame2.setFrameShape(QFrame.StyledPanel)
        
        right_layout = QVBoxLayout(self.frame2)

        self.frame = QFrame()
        self.frame.setFrameShape(QFrame.StyledPanel)
        
        left_layout = QVBoxLayout(self.frame)
        self.path = QLabel(self.parent_path)
        self.view_list = QListWidget()
        self.view_list.addItems(self.repo_dict[self.parent_path])

        right_layout.addWidget(self.button_create_repo)
        right_layout.addWidget(self.button_commit)
        right_layout.addWidget(self.button_branch)
        right_layout.addWidget(self.button_merge)
        right_layout.addWidget(self.button_check)
        right_layout.addWidget(self.repo_directory)
        right_layout.addWidget(self.button_reload)

        left_layout.addWidget(view_label)
        left_layout.addWidget(self.description_label)

        left_layout.addWidget(self.path)
        left_layout.addWidget(self.view_list)
        left_layout.addWidget(self.button_select)
        left_layout.addWidget(self.button_back)
        left_layout.addWidget(self.button_comment)
        left_layout.addWidget(self.button_download)
        left_layout.addWidget(self.button_download_path)

        self.layout_organizer.addWidget(self.frame)
        self.layout_organizer.addWidget(self.frame2)

        main_layout.addLayout(self.layout_organizer)


        self.setCentralWidget(main_widget)
        
        
    def repo_create(self):
        """
        Create the repository creator object
        """
        self.repo_creator = RepoCreate(self)
        self.repo_creator.show()

    def commit(self):
        """
        This method opens a commit window
        """
        self.commit_dialog = CommitDialog(self)
        self.commit_dialog.show()

    def branch(self):
        """
        This method opens a branch creation window
        """
        self.branch_dialog = BranchDialog(self)
        self.branch_dialog.show()

    def repo_location(self):
        """
        This method open the repository change window
        """
        self.repo_change = RepoChoose(self)
        self.repo_change.show()

    def merge_func(self):
        """
        This method opens the merge request window
        """
        self.merge_dialog = MergeDialog(self)
        self.merge_dialog.show()

    def check_requests(self):
        """
        This method asks the user about a commit\merge request, if indeed there is one.
        """
        request_list = requests_update()
        if request_list != [[]]:
            for request in request_list:
                directory, branch, user, title, comment, kind = request[0], request[1], request[2], request[4], request[5], request [7]
                request_string = "{0} Is asking for a {1} in directory {2} under branch {3}. Included Comments: {4}-{5}. \n Do you accept?".format(user,kind,directory,branch,title,comment)
                buttonReply = QMessageBox.question(self, 'Change Request', request_string, QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
                if buttonReply == QMessageBox.Yes:
                    answer_request(request,True)
                    self.reload()
                else:
                    answer_request(request,False)



    
    def download(self):
        """
        This method checks if files to download were selected, and summons the download function
        """
        if (self.directory == None):
            QMessageBox.warning(self, 'Download Error', 'Directory Selection Required')
            return
        download(self.directory[0], os.path.join(self.parent_path, self.view_list.selectedItems()[0].text()),self.view_list.selectedItems()[0].text())

    def download_path(self):
        """
        This method updates the download path with directory selected by the user
        """
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.Directory)
        if file_dialog.exec_():
            self.directory = file_dialog.selectedFiles()
        
    def select(self):
        """
        This method upadtes the repository view with the correct subfolders of the selected folder
        """
        try:
            item = self.view_list.selectedItems()[0].text()
        except:
            QMessageBox.warning(self, 'Selection Error', 'Must Select File or Directory')
            return
        if item.find(".") == -1: #If it contains a dot then it's a file and a not directory
            self.view_list.clear()
            self.parent_path = os.path.join(self.parent_path,item)
            self.path.setText(self.parent_path)
            self.path.update()
            self.view_list.addItems(self.repo_dict[self.parent_path])
            self.view_list.update()

    def back(self):
        """
        This method goes back to the parent folder of the current folder
        """
        if self.parent_path == os.path.join("C:\\RepoServer",self.repo):
            return
        
        self.view_list.clear()
        self.parent_path = os.path.dirname(self.parent_path)
        self.path.setText(self.parent_path)
        self.path.update()
        self.view_list.addItems(self.repo_dict[self.parent_path])
        self.view_list.update()

    def get_comment(self):
        """
        This method requests for the comment of a given version, if indeed a version was chosen.
        """
        try:
            item = self.view_list.selectedItems()[0].text()
        except:
            QMessageBox.warning(self, 'Selection Error', 'Must Select Commit')
            return
        comment = get_commit_comment(item, self.parent_path)
        info = QMessageBox.information(self,'Commit Comment', comment)

    def reload(self):
        """
        This method reload the repository view, using a summoning of appropriate functions for the retreival of info from the server.
        """
        self.repo = get_current_repo()
        self.repo_dict = repo_details()
        description = get_description()
        self.description_label.setText("Description: \n" + description)
        self.parent_path = os.path.join("C:\\RepoServer",self.repo)
        self.path.setText(self.parent_path)
        self.path.update()
        self.view_list.clear()
        self.view_list.addItems(self.repo_dict[self.parent_path])
        self.view_list.update()





                
                

    